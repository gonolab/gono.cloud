//! Names of devices as other devices show them (protocol 2.1).
//!
//! Names are self-asserted and reach approval prompts and notices on other devices, so they must
//! not be able to hide or reorder what the user reads: no control characters, no bidirectional
//! controls, and no invisible characters. Prompts show the short ID next to every name.

/// Longest name, in characters.
pub const MAX_NAME_CHARS: usize = 64;

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
}

impl NameError {
    /// The rule that was broken, for messages.
    pub fn reason(self) -> &'static str {
        match self {
            Self::Length => "must be 1 to 64 characters long",
            Self::Control => "must not contain control characters",
            Self::Bidi => "must not contain bidirectional controls",
            Self::Invisible => "must not contain invisible characters",
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
}
