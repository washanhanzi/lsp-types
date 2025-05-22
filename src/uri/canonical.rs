use fluent_uri::{
    component::{Authority, Scheme},
    encoding::{encoder::Userinfo, EStr},
};

use percent_encoding::{percent_encode, AsciiSet};
use std::{
    ops::Deref,
    path::{Component, Path, PathBuf},
};

use crate::Uri;

// Based on https://url.spec.whatwg.org/#path-percent-encode-set
// This set is used to encode path segments. It includes controls, space, quotes,
// and characters that have special meaning in URIs like '#', '?', '{', '}', '/', '%'.
const PATH_SEGMENT_ENCODE_SET: &AsciiSet = &percent_encoding::CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'<')
    .add(b'>')
    .add(b'`') // From FRAGMENT set
    .add(b'#')
    .add(b'?')
    .add(b'{')
    .add(b'}') // From PATH set
    .add(b'/')
    .add(b'%'); // Special to path segments themselves

#[derive(Debug, thiserror::Error)]
pub enum CanonicalUriError {
    #[error("Invalid URI: {0}")]
    InvalidUri(String),
    #[error("URI scheme is not 'file'")]
    NotFileScheme,
    #[error("Path canonicalization failed for '{path}': {source}")]
    CanonicalizationError {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("Cannot convert non-absolute path to URI: {0:?}")]
    NotAbsolutePath(PathBuf),
    #[error("URI does not have a path component")]
    UriMissingPath,
    #[error("URI path component is invalid for file path conversion: {0}")]
    InvalidUriPath(String),
    #[error("Failed to build URI: {0}")]
    UriBuildError(#[from] fluent_uri::error::BuildError),
    #[error("Path contains non-UTF8 characters or is invalid for URI: {0:?}")]
    InvalidPathChars(PathBuf),
    #[error("Fluent URI parse error: {0}")]
    FluentUriParseError(#[from] fluent_uri::error::ParseError),
    #[error("Windows URI path is malformed: {0}")]
    MalformedWindowsUriPath(String),
    #[error("Path component error on Windows: {0}")]
    WindowsPathComponentError(String),
    #[error("Unsupported URI authority for file path: {0}")]
    UnsupportedAuthority(String),
}

impl Uri {
    pub fn canonical(&self) -> Result<Uri, CanonicalUriError> {
        if self.scheme().as_str() != "file" {
            // For non-file URIs, parse the string representation to get an owned Uri<String>
            return Ok(Self(self.deref().to_owned()));
        }

        // For file URIs, the strategy is to convert to a PathBuf and then back to a Uri.
        // This leverages the canonicalization and formatting logic in `to_path_buf` and `try_from_path`.
        let path_buf: PathBuf = self.to_path_buf()?;
        // Convert &PathBuf to &Path using as_path() since we only implement TryFrom<&Path>
        Uri::try_from_path(&path_buf)
    }

    pub fn to_path_buf(&self) -> Result<PathBuf, CanonicalUriError> {
        if self.scheme().as_str() != "file" {
            return Err(CanonicalUriError::NotFileScheme);
        }

        let authority = self.authority();
        let host = authority.map(|auth| auth.host());
        let uri_fpath = self.path();

        #[cfg(windows)]
        {
            use percent_encoding::percent_decode_str;
            if host.is_some()
                && !host.unwrap().is_empty()
                && !host.unwrap().eq_ignore_ascii_case("localhost")
            {
                // UNC Path: file://server/share/path -> \\server\share\path
                let mut path_string = format!(r"\\{}", host.unwrap()); // host is already decoded by fluent_uri
                let path_str = uri_fpath.as_str();
                // Remove leading slash for correct segment splitting
                let path_str = if path_str.starts_with('/') {
                    &path_str[1..]
                } else {
                    path_str
                };
                for segment in path_str.split('/') {
                    if !segment.is_empty() {
                        path_string.push('\\');
                        // Decode percent-encoded segment
                        let decoded =
                            percent_encoding::percent_decode_str(segment).decode_utf8_lossy();
                        path_string.push_str(&decoded);
                    }
                }
                Ok(PathBuf::from(path_string))
            } else {
                // Local path: file:///C:/foo or file:///C%3A/foo or file:///c%3A/foo
                // The path part of the URI (uri_fpath.as_str()) is like "/C%3A/foo/bar.txt"
                let raw_path_str = uri_fpath.as_str();
                if !raw_path_str.starts_with('/') {
                    return Err(CanonicalUriError::MalformedWindowsUriPath(format!(
                        "File URI path must start with '/' for drive paths: '{}'",
                        raw_path_str
                    )));
                }
                // Decode the path component after the initial slash (e.g., "C%3A/foo/bar.txt" or "C:/foo/bar.txt")
                let decoded_path_part = percent_decode_str(&raw_path_str[1..]).decode_utf8_lossy();
                // PathBuf::from will correctly interpret "C:/foo/bar.txt" as "C:\foo\bar.txt"
                // and "C:/" as "C:\"
                Ok(PathBuf::from(decoded_path_part.into_owned()))
            }
        }
        #[cfg(not(windows))]
        {
            use percent_encoding::percent_decode_str;
            if host.is_some()
                && !host.unwrap().is_empty()
                && !host.unwrap().eq_ignore_ascii_case("localhost")
            {
                return Err(CanonicalUriError::UnsupportedAuthority(format!(
                    "Non-local host '{}' in file URI on non-Windows",
                    host.unwrap()
                )));
            }

            let decoded_path = percent_decode_str(uri_fpath.as_str()).decode_utf8_lossy();
            if !decoded_path.starts_with('/') && !decoded_path.is_empty() {
                // Allow "/" for root
                return Err(CanonicalUriError::InvalidUriPath(format!(
                    "File URI path must be absolute on non-Windows: '{decoded_path}'"
                )));
            }
            Ok(PathBuf::from(decoded_path.into_owned()))
        }
    }

    pub fn try_from_path(path: impl AsRef<Path>) -> Result<Self, CanonicalUriError> {
        let canonical_path =
            dunce::canonicalize(&path).map_err(|e| CanonicalUriError::CanonicalizationError {
                path: path.as_ref().to_path_buf(),
                source: e,
            })?;
        let mut path_str = String::new();
        let authority_opt: Option<String>;

        #[cfg(windows)]
        {
            use std::path::Prefix;
            let mut components_iter = canonical_path.components();
            match components_iter.next() {
                Some(Component::Prefix(prefix_component)) => {
                    match prefix_component.kind() {
                        Prefix::Disk(drive_letter) | Prefix::VerbatimDisk(drive_letter) => {
                            path_str.push('/'); // URI path starts with /
                            path_str.push((drive_letter as char).to_ascii_lowercase());
                            path_str.push_str("%3A"); // Standardized colon: e.g. /c%3A
                                                      // Create an empty authority string for file:///
                            authority_opt = Some("".to_string());
                        }
                        Prefix::UNC(server, share) | Prefix::VerbatimUNC(server, share) => {
                            let server_str = server.to_str().ok_or_else(|| {
                                CanonicalUriError::InvalidPathChars(PathBuf::from(server))
                            })?;
                            let share_str = share.to_str().ok_or_else(|| {
                                CanonicalUriError::InvalidPathChars(PathBuf::from(share))
                            })?;
                            // Store server string directly for the authority part
                            let server_authority = server_str.to_string();
                            // Just use the server string directly as the authority
                            authority_opt = Some(server_authority);

                            // Path for UNC starts with /share
                            path_str.push('/');
                            path_str.push_str(
                                &percent_encode(share_str.as_bytes(), PATH_SEGMENT_ENCODE_SET)
                                    .to_string(),
                            );
                        }
                        _ => {
                            return Err(CanonicalUriError::WindowsPathComponentError(format!(
                                "Unsupported path prefix: {:?}",
                                prefix_component.kind()
                            )))
                        }
                    }
                }
                _ => return Err(CanonicalUriError::NotAbsolutePath(canonical_path)),
            }

            // Append remaining path segments
            let mut first_segment_after_prefix_or_share = true;
            for component in components_iter {
                match component {
                    Component::RootDir => {
                        // e.g., the '\' in "C:\" or after share in UNC
                        if !path_str.ends_with('/') {
                            // Ensure path like /c%3A gets /c%3A/
                            path_str.push('/');
                        }
                        first_segment_after_prefix_or_share = true;
                    }
                    Component::Normal(segment) => {
                        if !first_segment_after_prefix_or_share && !path_str.ends_with('/') {
                            path_str.push('/');
                        } else if first_segment_after_prefix_or_share && !path_str.ends_with('/') {
                            path_str.push('/');
                        }

                        let seg_str = segment.to_str().ok_or_else(|| {
                            CanonicalUriError::InvalidPathChars(canonical_path.clone())
                        })?;
                        path_str.push_str(
                            &percent_encode(seg_str.as_bytes(), PATH_SEGMENT_ENCODE_SET)
                                .to_string(),
                        );
                        first_segment_after_prefix_or_share = false;
                    }
                    _ => {} // Ignore CurDir, ParentDir as path is canonical
                }
            }
            // Ensure drive root path like C:\ (which becomes /c%3A after prefix handling) ends with a slash.
            // If path_str is "/c%3A" and there were no further components other than potentially RootDir.
            if authority_opt
                .as_ref()
                .map_or(false, |a| a.as_str().is_empty())
                && path_str.ends_with("%3A")
            {
                path_str.push('/'); // For "C:" -> "/c%3A/"
            }
        }
        #[cfg(not(windows))]
        {
            if !canonical_path.is_absolute() {
                return Err(CanonicalUriError::NotAbsolutePath(canonical_path));
            }
            // Create an empty authority string for file:///
            authority_opt = Some("".to_string());

            let mut components = canonical_path.components().peekable();
            if let Some(Component::RootDir) = components.peek() {
                path_str.push('/');
                components.next(); // Consume RootDir
            } else {
                // This should not happen for absolute Unix paths from canonicalize
                return Err(CanonicalUriError::InvalidPathChars(
                    format!(
                        "Absolute Unix path expected to start with RootDir: {canonical_path:?}"
                    )
                    .into(),
                ));
            }

            let mut first_component_after_root = true;
            for component in components {
                if let Component::Normal(segment) = component {
                    if !first_component_after_root {
                        path_str.push('/');
                    }
                    let seg_str = segment.to_str().ok_or_else(|| {
                        CanonicalUriError::InvalidPathChars(canonical_path.clone())
                    })?;
                    path_str.push_str(
                        &percent_encode(seg_str.as_bytes(), PATH_SEGMENT_ENCODE_SET).to_string(),
                    );
                    first_component_after_root = false;
                }
            }
            // If path was "/" (root), path_str is now "/". Correct.
        }

        // Normalize path by replacing any double slashes with single slashes
        // Keep replacing until no more double slashes are found
        let mut normalized_path = path_str;
        while normalized_path.contains("//") {
            normalized_path = normalized_path.replace("//", "/");
        }

        let fluent_path_estr = EStr::new(&normalized_path)
            .ok_or(CanonicalUriError::InvalidPathChars(canonical_path))?;

        // Instead of conditionally setting properties, let's build the URI directly with the fluent builder pattern
        let result = if let Some(auth_str) = authority_opt {
            // If we have authority, create a temporary URI to extract the properly formatted authority
            if auth_str.is_empty() {
                // For empty authority (file:///)
                fluent_uri::Uri::<String>::builder()
                    .scheme(Scheme::new("file").unwrap())
                    .authority(Authority::<Userinfo>::EMPTY)
                    .path(fluent_path_estr)
                    .build()
            } else {
                // For non-empty authority (like UNC paths)
                // Parse a temp URI to get a properly formatted authority object
                let temp_uri = fluent_uri::Uri::<String>::parse(format!("scheme://{auth_str}"))
                    .map_err(|_| CanonicalUriError::UnsupportedAuthority(auth_str.clone()))?;

                fluent_uri::Uri::<String>::builder()
                    .scheme(Scheme::new("file").unwrap())
                    .authority(temp_uri.authority().unwrap().to_owned())
                    .path(fluent_path_estr)
                    .build()
            }
        } else {
            // If we don't have authority
            fluent_uri::Uri::<String>::builder()
                .scheme(Scheme::new("file").unwrap())
                .path(fluent_path_estr)
                .build()
        };

        result.map(Self).map_err(CanonicalUriError::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, str::FromStr};
    use tempfile::tempdir;

    #[test]
    #[cfg(windows)]
    fn test_windows_into_path() {
        assert_eq!(
            Uri::from_str("file:///c%3A/project/readme.md")
                .unwrap()
                .to_path_buf()
                .unwrap(),
            PathBuf::from(r"C:\project\readme.md")
        );
        assert_eq!(
            Uri::from_str("file:///C%3A/Users/User/file.txt")
                .unwrap()
                .to_path_buf()
                .unwrap(),
            PathBuf::from(r"C:\Users\User\file.txt")
        );
        assert_eq!(
            Uri::from_str("file:///C:/Windows/System32")
                .unwrap()
                .to_path_buf()
                .unwrap(),
            PathBuf::from(r"C:\Windows\System32")
        );
        assert_eq!(
            Uri::from_str("file:///d%3a/test.txt")
                .unwrap()
                .to_path_buf()
                .unwrap(),
            PathBuf::from(r"D:\test.txt")
        );
        assert_eq!(
            Uri::from_str("file://localhost/C:/Users/foo.txt")
                .unwrap()
                .to_path_buf()
                .unwrap(),
            PathBuf::from(r"C:\Users\foo.txt")
        );
        assert_eq!(
            Uri::from_str("file://server/share/file.txt")
                .unwrap()
                .to_path_buf()
                .unwrap(),
            PathBuf::from(r"\\server\share\file.txt")
        );
        assert_eq!(
            Uri::from_str("file:///C%3A/")
                .unwrap()
                .to_path_buf()
                .unwrap(),
            PathBuf::from(r"C:\")
        );
        assert_eq!(
            Uri::from_str("file:///D:/").unwrap().to_path_buf().unwrap(),
            PathBuf::from(r"D:\")
        );
        assert_eq!(
            Uri::from_str("file:///c%3A/path%20with%20spaces/file.txt")
                .unwrap()
                .to_path_buf()
                .unwrap(),
            PathBuf::from(r"C:\path with spaces\file.txt")
        );
    }

    #[test]
    #[cfg(not(windows))]
    fn test_unix_into_path() {
        use std::str::FromStr;

        assert_eq!(
            Uri::from_str("file:///home/user/file.txt")
                .unwrap()
                .to_path_buf()
                .unwrap(),
            PathBuf::from("/home/user/file.txt")
        );
        assert_eq!(
            Uri::from_str("file:///etc/hosts")
                .unwrap()
                .to_path_buf()
                .unwrap(),
            PathBuf::from("/etc/hosts")
        );
        assert_eq!(
            Uri::from_str("file:///").unwrap().to_path_buf().unwrap(),
            PathBuf::from("/")
        );
        assert_eq!(
            Uri::from_str("file://localhost/tmp/test")
                .unwrap()
                .to_path_buf()
                .unwrap(),
            PathBuf::from("/tmp/test")
        );
        assert!(Uri::from_str("file://otherhost/tmp/test")
            .unwrap()
            .to_path_buf()
            .is_err());
        assert_eq!(
            Uri::from_str("file:///path%20with%20spaces/file.txt")
                .unwrap()
                .to_path_buf()
                .unwrap(),
            PathBuf::from("/path with spaces/file.txt")
        );
    }

    #[test]
    #[cfg(windows)]
    fn test_windows_into_uri() {
        use std::path::Prefix;

        let temp_dir = tempdir().unwrap(); // Create temp dir on a real drive
        let project_dir = temp_dir.path().join("project");
        fs::create_dir(&project_dir).unwrap();
        let readme_file = project_dir.join("readme.md");
        fs::File::create(&readme_file).unwrap();

        let canonical_readme_path = dunce::canonicalize(&readme_file).unwrap();
        let drive_letter = canonical_readme_path
            .components()
            .next()
            .and_then(|c| match c {
                Component::Prefix(p) => match p.kind() {
                    Prefix::Disk(d) | Prefix::VerbatimDisk(d) => {
                        Some((d as char).to_ascii_lowercase())
                    }
                    _ => None,
                },
                _ => None,
            })
            .expect("Should have drive letter on Windows");

        let expected_readme_uri_str = format!(
            "file:///{drive_letter}%3A{}{}/project/readme.md",
            drive_letter,
            dunce::canonicalize(temp_dir.path())
                .unwrap()
                .strip_prefix(PathBuf::from(format!(
                    "{}:\\",
                    drive_letter.to_ascii_uppercase()
                )))
                .unwrap()
                .to_string_lossy()
                .replace("\\", "/")
        );
        // The above path reconstruction for test is too complex and brittle.
        // Simpler test: take a known canonical path and check its URI form.

        // Test with a specific file that we know exists on Windows systems
        let system_file = Path::new("C:\\Windows\\System32\\notepad.exe");
        if system_file.exists() {
            let uri_file = Uri::try_from_path(system_file).unwrap();
            assert_eq!(
                uri_file.as_str(),
                "file:///c%3A/Windows/System32/notepad.exe"
            );
        }

        // Test path with spaces
        let path_with_spaces = temp_dir.path().join("file with spaces.txt");
        fs::File::create(&path_with_spaces).unwrap();
        let canonical_spaces_path = dunce::canonicalize(&path_with_spaces).unwrap();

        let drive_letter_spaces = canonical_spaces_path
            .components()
            .next()
            .and_then(|c| match c {
                Component::Prefix(p) => match p.kind() {
                    Prefix::Disk(d) | Prefix::VerbatimDisk(d) => {
                        Some((d as char).to_ascii_lowercase())
                    }
                    _ => None,
                },
                _ => None,
            })
            .unwrap();
        // Construct expected path carefully based on components of canonical_spaces_path
        let mut expected_path_part_for_spaces = format!("/{drive_letter_spaces}%3A");
        let mut first = true;
        for component in canonical_spaces_path.components().skip(1) {
            // Skip prefix
            if !first || !expected_path_part_for_spaces.ends_with('/') {
                expected_path_part_for_spaces.push('/');
            }
            if let Component::Normal(name) = component {
                expected_path_part_for_spaces.push_str(
                    &percent_encode(name.to_str().unwrap().as_bytes(), PATH_SEGMENT_ENCODE_SET)
                        .to_string(),
                );
            }
            first = false;
        }
        if canonical_spaces_path.ends_with("\\") && !expected_path_part_for_spaces.ends_with('/') {
            // For directories like C:\temp\
            expected_path_part_for_spaces.push('/');
        }

        let uri_spaces = Uri::try_from_path(&path_with_spaces).unwrap();

        // Get the actual path and normalize it for comparison
        let actual_path = uri_spaces.path().as_str();
        let mut normalized_actual = actual_path.to_string();
        while normalized_actual.contains("//") {
            normalized_actual = normalized_actual.replace("//", "/");
        }

        // Also normalize the expected path
        let mut normalized_expected = expected_path_part_for_spaces.clone();
        while normalized_expected.contains("//") {
            normalized_expected = normalized_expected.replace("//", "/");
        }

        // Compare normalized paths
        assert_eq!(normalized_actual, normalized_expected);
        assert_eq!(uri_spaces.scheme().as_str(), "file");
        assert_eq!(uri_spaces.authority().unwrap().as_str(), "");

        // Test UNC path if possible (hard to test without actual UNC or mocking)
        // let unc_path = Path::new(r"\\testserver\testshare\file.txt");
        // if unc_path.exists() { // This check itself requires access
        //     let uri_unc = into_uri(unc_path).unwrap();
        //     assert_eq!(uri_unc.as_str(), "file://testserver/testshare/file.txt");
        // }
    }

    #[test]
    #[cfg(not(windows))]
    fn test_unix_into_uri() {
        let temp_dir = tempdir().unwrap();
        let dir_path = temp_dir.path().join("my dir");
        fs::create_dir(&dir_path).unwrap();
        let file_path = dir_path.join("file with spaces.txt");
        fs::File::create(&file_path).unwrap();

        // Convert &PathBuf to &Path using as_path() since we only implement TryFrom<&Path>
        let uri = Uri::try_from_path(file_path.as_path()).unwrap();
        let canonical_file_path_str = dunce::canonicalize(&file_path)
            .unwrap()
            .to_string_lossy()
            .to_string();

        // Expected path: /actual_canonical_temp_dir_path/my%20dir/file%20with%20spaces.txt
        let expected_uri_path = canonical_file_path_str
            .replace("my dir", "my%20dir")
            .replace("file with spaces.txt", "file%20with%20spaces.txt");

        assert_eq!(uri.scheme().as_str(), "file");
        assert_eq!(uri.authority().unwrap().as_str(), ""); // Empty for file:///
        assert_eq!(uri.path().as_str(), expected_uri_path);
        assert_eq!(uri.as_str(), format!("file://{expected_uri_path}"));

        let root_path = Path::new("/");
        let uri_root = Uri::try_from_path(root_path).unwrap();
        assert_eq!(uri_root.as_str(), "file:///");
    }

    #[test]
    #[cfg(windows)]
    fn test_windows_standardize_uri() {
        let windows_path_for_test = Path::new("C:\\Windows");
        if !windows_path_for_test.exists() {
            eprintln!("Skipping test_windows_standardize_uri parts as C:\\Windows does not exist.");
            return;
        }

        let inputs = [
            "file:///c:/Windows",
            "file:///C%3A/Windows", //fluent_uri path.segments() will provide "C%3A" as a segment if not standardly encoded
            "file:///C:/Windows",   //path.segments() will provide "C:"
            "file:///c%3a/Windows", // same as C%3A for segments
        ];
        // Canonicalization (via into_path -> into_uri) will determine actual casing of "Windows"
        let canonical_windows_path = dunce::canonicalize(windows_path_for_test).unwrap();
        let expected_uri_obj = Uri::try_from_path(&canonical_windows_path).unwrap(); // This is our standard
        let expected_str = expected_uri_obj.as_str();

        for input_str in inputs {
            let uri = Uri::from_str(input_str).unwrap();
            let standardized = uri.canonical().unwrap();
            assert_eq!(
                standardized.as_str(),
                expected_str,
                "Failed for input: {}",
                input_str
            );
        }

        // Test with a non-existent path (should fail canonicalization)
        let non_existent_uri =
            Uri::from_str("file:///c%3A/some/truly/non/existent/path.txt").unwrap();
        assert!(non_existent_uri.canonical().is_err());
    }

    #[test]
    fn test_non_file_uri_standardize() {
        let http_uri_str = "http://example.com/path?query#fragment";
        let http_uri = Uri::from_str(http_uri_str).unwrap();
        let canonical_http: Uri = http_uri.canonical().unwrap();
        assert_eq!(canonical_http.as_str(), http_uri_str);

        let mailto_uri_str = "mailto:user@example.com";
        let mailto_uri = Uri::from_str(mailto_uri_str).unwrap();
        let canonical_mailto: Uri = mailto_uri.canonical().unwrap();
        assert_eq!(canonical_mailto.as_str(), mailto_uri_str);
    }
}
