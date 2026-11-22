//! QR codes as inline SVG, for the enrolment of two-step verification and the WeChat bind
//! tickets of the account page. The pages need no script, and the SVG has no style attributes,
//! so the Content Security Policy stays strict.

use std::fmt::Write as _;

use qrcodegen::{QrCode, QrCodeEcc};

/// Modules of quiet zone around the code.
const BORDER: i32 = 4;

/// `text` as an SVG QR code: black modules on white, whatever the page's theme, so that
/// cameras read it.
pub fn svg(text: &str) -> Option<String> {
    let code = QrCode::encode_text(text, QrCodeEcc::Medium).ok()?;
    let size = code.size();
    let mut path = String::new();
    for y in 0..size {
        for x in 0..size {
            if code.get_module(x, y) {
                let _ = write!(path, "M{},{}h1v1h-1z", x + BORDER, y + BORDER);
            }
        }
    }
    let side = size + 2 * BORDER;
    Some(format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" class=\"qr\" viewBox=\"0 0 {side} {side}\" \
         role=\"img\" aria-label=\"QR code\" shape-rendering=\"crispEdges\">\
         <rect width=\"{side}\" height=\"{side}\" fill=\"#fff\"/>\
         <path d=\"{path}\" fill=\"#000\"/></svg>"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_are_svg_without_styles() {
        let svg = svg("otpauth://totp/Gono%20Cloud:kim?secret=ABCD").unwrap();
        assert!(svg.starts_with("<svg ") && svg.ends_with("</svg>"));
        assert!(!svg.contains("style"));
        assert!(svg.contains("M4,4h1v1h-1z"), "the finder pattern's corner");
    }
}
