//! Unit tests for escape sequence parser.

use super::*;

#[test]
fn escape_at_line_start_disconnect_and_literal() {
    let mut p = EscapeParser::default();
    let (actions, out) = p.process(b"~.");
    assert!(out.is_empty());
    assert!(actions.iter().any(|a| matches!(a, EscapeAction::Disconnect)));

    // literal ~~ should output a single ~ and not produce actions (other than LiteralTilde)
    let (actions2, out2) = p.process(b"~~x\n");
    assert_eq!(out2, b"~x\n");
    assert!(actions2.iter().any(|a| matches!(a, EscapeAction::LiteralTilde)));
}

#[test]
fn escape_only_at_line_start() {
    let mut p = EscapeParser::default();
    let (_a1, out1) = p.process(b"abc");
    assert_eq!(out1, b"abc");
    // Not at line start, so '~R' should pass through
    let (a2, out2) = p.process(b"~R\n");
    assert!(a2.is_empty());
    assert_eq!(out2, b"~R\n");
    // Now at line start; '~#' triggers action
    let (a3, out3) = p.process(b"~#");
    assert!(out3.is_empty());
    assert!(a3.iter().any(|a| matches!(a, EscapeAction::ListForwards)));
}
