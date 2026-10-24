/// Return the application version.
///
/// This should be in sync with uv's version based on the Crate version.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Return the application version without prerelease or build metadata suffixes.
pub fn version_without_suffix() -> &'static str {
    strip_version_suffix(version())
}

fn strip_version_suffix(version: &str) -> &str {
    version
        .split_once(['-', '+'])
        .map_or(version, |(release, _)| release)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_version() {
        assert_eq!(version().to_string(), env!("CARGO_PKG_VERSION").to_string());
    }

    #[test]
    fn test_version_without_suffix() {
        assert_eq!(strip_version_suffix("0.13.5"), "0.13.5");
    }

    #[test]
    fn test_version_without_build_metadata() {
        assert_eq!(strip_version_suffix("0.13.5+codeartifact.1"), "0.13.5");
    }

    #[test]
    fn test_version_without_prerelease() {
        assert_eq!(strip_version_suffix("0.13.5-rc.1+codeartifact.1"), "0.13.5");
    }
}
