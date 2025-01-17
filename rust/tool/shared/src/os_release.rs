use std::fmt;
use std::{collections::BTreeMap, str::FromStr};

use anyhow::Result;

use crate::generation::Generation;

/// An os-release file represented by a BTreeMap.
///
/// This is implemented using a map, so that it can be easily extended in the future (e.g. by
/// reading the original os-release and patching it).
///
/// The BTreeMap is used over a HashMap, so that the keys are ordered. This is irrelevant for
/// systemd-boot (which does not care about order when reading the os-release file) but is useful
/// for testing. Ordered keys allow using snapshot tests.
pub struct OsRelease(pub BTreeMap<String, String>);

impl OsRelease {
    pub fn from_generation(generation: &Generation) -> Result<Self> {
        let mut map = BTreeMap::new();

        // Because of a null pointer dereference, `bootctl` segfaults when no ID field is present
        // in the .osrel section of the stub.
        // Fixed in https://github.com/systemd/systemd/pull/25953
        //
        // Because the ID field here does not have the same meaning as in a real os-release file,
        // it is fine to use a dummy value.
        map.insert(
            "ID".into(),
            generation.spec.lanzaboote_extension.sort_key.clone(),
        );

        // systemd-boot will only show VERSION_ID when PRETTY_NAME is not unique. This is
        // confusing to users. Make sure that our PRETTY_NAME is unique, so we get a consistent
        // user experience.
        //
        // See #220.
        map.insert(
            "PRETTY_NAME".into(),
            format!(
                "{} ({})",
                generation.spec.bootspec.bootspec.label,
                generation.describe()
            ),
        );

        map.insert("VERSION_ID".into(), generation.describe());

        Ok(Self(map))
    }

    pub fn pretty_name(&self) -> &str {
        self.0
            .get("PRETTY_NAME")
            .map(|v| v.as_str())
            .unwrap_or_default()
    }
    pub fn version_id(&self) -> &str {
        self.0
            .get("VERSION_ID")
            .map(|v| v.as_str())
            .unwrap_or_default()
    }
}

impl FromStr for OsRelease {
    type Err = anyhow::Error;
    /// Parse the string representation of a os-release file.
    ///
    /// **Beware before reusing this function!**
    ///
    /// This parser might not parse all valid os-release files correctly. It is only designed to
    /// read the `VERSION` key from the os-release of a systemd-boot binary.
    fn from_str(value: &str) -> Result<Self> {
        let mut map = BTreeMap::new();

        enum State {
            PreKey,
            Key,
            PreValue,
            Value,
            ValueEscape,
            SingleQuoteValue,
            DoubleQuoteValue,
            DoubleQuoteValueEscape,
            Comment,
            CommentEscape,
        }
        use State::*;

        let mut state = State::PreKey;

        let mut current_key = String::new();
        let mut current_value = String::new();

        const COMMENTS: &str = "#;";
        const WHITESPACE: &str = " \t\n\r";
        const NEWLINE: &str = "\r\n";
        const SHELL_NEED_ESCAPE: &str = "\"\\`$";

        for c in value.chars() {
            match state {
                PreKey => {
                    if COMMENTS.contains(c) {
                        state = Comment;
                    } else if !WHITESPACE.contains(c) {
                        state = Key;
                        current_key.push(c);
                    }
                }
                Key => {
                    if NEWLINE.contains(c) {
                        // keys without any '=' are simply ignored
                        state = PreKey;
                        current_key.clear();
                    } else if c == '=' {
                        state = PreValue;
                    } else {
                        current_key.push(c);
                    }
                }
                PreValue => {
                    if NEWLINE.contains(c) {
                        state = PreKey;
                        // strip trailing whitespace from key
                        let key = current_key.trim_end().to_owned();
                        map.insert(key, current_value.clone());

                        current_key.clear();
                        current_value.clear();
                    } else if c == '\'' {
                        state = SingleQuoteValue;
                    } else if c == '"' {
                        state = DoubleQuoteValue;
                    } else if c == '\\' {
                        state = ValueEscape;
                    } else if !WHITESPACE.contains(c) {
                        state = Value;
                        current_value.push(c);
                    }
                }
                Value => {
                    if NEWLINE.contains(c) {
                        state = PreKey;
                        // strip trailing whitespace from key
                        let key = current_key.trim_end().to_owned();
                        // strip trailing whitespace from value
                        let value = current_value.trim_end().to_owned();
                        map.insert(key, value);

                        current_key.clear();
                        current_value.clear();
                    } else if c == '\\' {
                        state = ValueEscape;
                    } else {
                        current_value.push(c);
                    }
                }
                ValueEscape => {
                    state = Value;

                    if !NEWLINE.contains(c) {
                        // Escaped newlines we eat up entirely
                        current_value.push(c);
                    }
                }
                SingleQuoteValue => {
                    if c == '\'' {
                        state = PreValue;
                    } else {
                        current_value.push(c);
                    }
                }
                DoubleQuoteValue => {
                    if c == '"' {
                        state = PreValue;
                    } else if c == '\\' {
                        state = DoubleQuoteValueEscape;
                    } else {
                        current_value.push(c);
                    }
                }
                DoubleQuoteValueEscape => {
                    state = DoubleQuoteValue;

                    if SHELL_NEED_ESCAPE.contains(c) {
                        // If this is a char that needs escaping, just unescape it.
                        current_value.push(c);
                    } else if c != '\n' {
                        // If other char than what needs escaping, keep the "\"
                        // in place, like the real shell does.
                        current_value.push('\\');
                        current_value.push(c);
                    }
                    // Escaped newlines (aka "continuation lines") are eaten up entirely
                }
                Comment => {
                    if c == '\\' {
                        state = CommentEscape;
                    } else if NEWLINE.contains(c) {
                        state = PreKey;
                    }
                }
                CommentEscape => {
                    log::debug!("The line which doesn't begin with \";\" or \"#\", but follows a comment line trailing with escape is now treated as a non comment line since v254.");
                    if NEWLINE.contains(c) {
                        state = PreKey;
                    } else {
                        state = Comment;
                    }
                }
            }
        }

        if matches!(
            state,
            PreValue
                | Value
                | ValueEscape
                | SingleQuoteValue
                | DoubleQuoteValue
                | DoubleQuoteValueEscape
        ) {
            // strip trailing whitespace from key
            let key = current_key.trim_end().to_owned();
            let value = if matches!(state, Value) {
                // strip trailing whitespace from value
                current_value.trim_end().to_owned()
            } else {
                current_value
            };
            map.insert(key, value);
        }

        Ok(Self(map))
    }
}

/// Display OsRelease in the format of an os-release file.
impl fmt::Display for OsRelease {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for (key, value) in &self.0 {
            writeln!(f, "{}={}", key, value)?
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CStr;

    #[test]
    fn parses_correctly_from_str() -> Result<()> {
        let os_release_cstr = CStr::from_bytes_with_nul(b"ID=systemd-boot\nVERSION=\"252.1\"\n\0")?;
        let os_release_str = os_release_cstr.to_str()?;
        let os_release = OsRelease::from_str(os_release_str)?;

        assert!(os_release.0["ID"] == "systemd-boot");
        assert!(os_release.0["VERSION"] == "252.1");

        Ok(())
    }

    #[test]
    fn escaping_works() -> Result<()> {
        let teststring = r#"
            NO_QUOTES=systemd-boot
            DOUBLE_QUOTES="systemd-boot"
            SINGLE_QUOTES='systemd-boot'
            UNESCAPED_DOLLAR=$1.2
            ESCAPED_DOLLAR=\$1.2
            UNESCAPED_BACKTICK=`1.2
            ESCAPED_BACKTICK=\`1.2
            UNESCAPED_QUOTE=""1.2"
            ESCAPED_QUOTE=\"1.2
        "#;
        let os_release = OsRelease::from_str(teststring)?;

        assert!(os_release.0["NO_QUOTES"] == "systemd-boot");
        assert!(os_release.0["DOUBLE_QUOTES"] == "systemd-boot");
        assert!(os_release.0["SINGLE_QUOTES"] == "systemd-boot");
        assert!(os_release.0["UNESCAPED_DOLLAR"] == "$1.2");
        assert!(os_release.0["ESCAPED_DOLLAR"] == "$1.2");
        assert!(os_release.0["UNESCAPED_BACKTICK"] == "`1.2");
        assert!(os_release.0["ESCAPED_BACKTICK"] == "`1.2");
        assert!(os_release.0["UNESCAPED_QUOTE"] == "1.2\"");
        assert!(os_release.0["ESCAPED_QUOTE"] == "\"1.2");

        Ok(())
    }
}
