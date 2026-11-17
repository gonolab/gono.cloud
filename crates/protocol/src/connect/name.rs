//! Names of devices as other devices show them (protocol 2.1).
//!
//! Names are self-asserted and reach approval prompts and notices on other devices, so they must
//! not be able to hide or reorder what the user reads: no control characters, no bidirectional
//! controls, and no invisible characters. Prompts show the short ID next to every name.
//!
//! - [`check_name`] for a name a device sends on its own, at registration or in a rename: the
//!   server trims it and stores the result.
//! - [`check_statement_name`] for a name inside a signed statement, which the server relays byte
//!   for byte and cannot trim: it must be trimmed already.
//! - [`is_slug`] for the `product` and `platform` shown next to a name.

/// Longest name, in characters.
pub const MAX_NAME_CHARS: usize = 64;

/// Longest `product` or `platform`, in characters.
pub const MAX_SLUG_CHARS: usize = 32;

/// Why a name is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameError {
    /// Empty after trimming, or longer than [`MAX_NAME_CHARS`].
    Length,
    /// A control character.
    Control,
    /// A bidirectional control (U+202A–U+202E, U+2066–U+2069).
    Bidi,
    /// An invisible character: zero-width, a filler, a variation selector, a tag, …
    Invisible,
    /// White space at the start or the end of a name inside a signed statement.
    Untrimmed,
}

impl NameError {
    /// The rule that was broken, for messages.
    pub fn reason(self) -> &'static str {
        match self {
            Self::Length => "must be 1 to 64 characters long",
            Self::Control => "must not contain control characters",
            Self::Bidi => "must not contain bidirectional controls",
            Self::Invisible => "must not contain invisible characters",
            Self::Untrimmed => "must not start or end with white space",
        }
    }
}

impl std::fmt::Display for NameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.reason())
    }
}

impl std::error::Error for NameError {}

/// Checks a name as protocol 2.1 says and returns it trimmed.
pub fn check_name(name: &str) -> Result<&str, NameError> {
    let name = name.trim();
    if name.is_empty() || name.chars().count() > MAX_NAME_CHARS {
        return Err(NameError::Length);
    }
    for c in name.chars() {
        if c.is_control() {
            return Err(NameError::Control);
        }
        if is_bidi_control(c) {
            return Err(NameError::Bidi);
        }
        if is_invisible(c) {
            return Err(NameError::Invisible);
        }
    }
    Ok(name)
}

/// Checks a name inside a signed statement (`pair-request`, `pair-approval`) as protocol 2.1
/// says. Statements travel unchanged, so the name is checked as it is: white space at its
/// edges, which [`check_name`] would trim away first, is refused. Otherwise line breaks,
/// carriage returns and padding at the edges would reach the approver's prompt and could push
/// the short ID out of view.
pub fn check_statement_name(name: &str) -> Result<&str, NameError> {
    if name.trim() != name {
        return Err(NameError::Untrimmed);
    }
    check_name(name)
}

/// Whether `value` is a valid `product` or `platform` (protocol 2.1): `[a-z0-9-]{1,32}`.
/// Approvers show the `platform` of a pairing statement next to the name, so these are checked
/// in statements as well as at registration.
pub fn is_slug(value: &str) -> bool {
    (1..=MAX_SLUG_CHARS).contains(&value.len())
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

fn is_bidi_control(c: char) -> bool {
    matches!(c, '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
}

/// Characters that render as nothing (default-ignorable code points and blank fillers), which
/// could make two different names look alike. U+200D (zero-width joiner) is included: it joins
/// emoji, but a device name does not need it.
fn is_invisible(c: char) -> bool {
    matches!(
        c,
        '\u{00AD}'
            | '\u{034F}'
            | '\u{061C}'
            | '\u{115F}'
            | '\u{1160}'
            | '\u{17B4}'
            | '\u{17B5}'
            | '\u{180B}'..='\u{180F}'
            | '\u{200B}'..='\u{200F}'
            | '\u{2028}'
            | '\u{2029}'
            | '\u{2060}'..='\u{206F}'
            | '\u{3164}'
            | '\u{FE00}'..='\u{FE0F}'
            | '\u{FEFF}'
            | '\u{FFA0}'
            | '\u{FFF0}'..='\u{FFFB}'
            | '\u{E0000}'..='\u{E0FFF}'
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordinary_names_pass_trimmed() {
        assert_eq!(check_name("  Work PC "), Ok("Work PC"));
        assert_eq!(check_name("小明的 iPhone"), Ok("小明的 iPhone"));
        assert_eq!(check_name("Café — Büro"), Ok("Café — Büro"));
        assert_eq!(check_name(&"x".repeat(64)), Ok(&*"x".repeat(64)));
    }

    #[test]
    fn names_that_hide_or_reorder_text_are_refused() {
        assert_eq!(check_name(""), Err(NameError::Length));
        assert_eq!(check_name("   "), Err(NameError::Length));
        assert_eq!(check_name(&"x".repeat(65)), Err(NameError::Length));
        assert_eq!(check_name("Home\nPC"), Err(NameError::Control));
        assert_eq!(check_name("Home\u{7}PC"), Err(NameError::Control));
        assert_eq!(check_name("Home \u{202E}CP"), Err(NameError::Bidi));
        assert_eq!(check_name("\u{2067}Home PC"), Err(NameError::Bidi));
        assert_eq!(check_name("Home\u{200B}PC"), Err(NameError::Invisible));
        assert_eq!(check_name("Home PC\u{FEFF}"), Err(NameError::Invisible));
        assert_eq!(check_name("Home\u{3164}PC"), Err(NameError::Invisible));
        assert_eq!(check_name("Home PC\u{E0041}"), Err(NameError::Invisible));
    }

    #[test]
    fn statement_names_must_be_trimmed_already() {
        assert_eq!(check_statement_name("Work PC"), Ok("Work PC"));
        assert_eq!(check_statement_name("小明的 iPhone"), Ok("小明的 iPhone"));
        for name in [
            " Work PC",
            "Work PC ",
            "Work PC\r",
            "\nWork PC",
            "Work PC\u{85}",
            "\u{2028}Work PC",
            "Work PC\u{3000}\u{3000}",
            "\u{A0}Work PC",
        ] {
            assert_eq!(
                check_statement_name(name),
                Err(NameError::Untrimmed),
                "{name:?}"
            );
        }
        // The other rules still hold.
        assert_eq!(check_statement_name(""), Err(NameError::Length));
        assert_eq!(check_statement_name("Home\nPC"), Err(NameError::Control));
        assert_eq!(
            check_statement_name("Home \u{202E}CP"),
            Err(NameError::Bidi)
        );
    }

    #[test]
    fn slugs() {
        for slug in ["input-show", "windows", "harmonyos", "a", &"a".repeat(32)] {
            assert!(is_slug(slug), "{slug:?}");
        }
        for value in [
            "",
            "Input Show",
            "Windows",
            "ios\u{202E}",
            "mac\nos",
            "macos ",
            "\u{FF4D}acos",
            &"a".repeat(33),
        ] {
            assert!(!is_slug(value), "{value:?}");
        }
    }
}
