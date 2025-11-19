use tui_core::input;

#[test]
fn lf_maps_to_cr() {
    let out = input::canonicalize(b"\n");
    assert_eq!(out, input::ENTER);
}

#[test]
fn backspace_normalized() {
    let out = input::canonicalize(&[0x08]);
    assert_eq!(out, input::BACKSPACE);
}

#[test]
fn delete_maps_to_backspace() {
    let out = input::canonicalize(input::DELETE_SEQ);
    assert_eq!(out, input::BACKSPACE);
}

#[test]
fn arrows_passthrough() {
    for seq in [input::ARROW_UP, input::ARROW_DOWN, input::ARROW_LEFT, input::ARROW_RIGHT] {
        let out = input::canonicalize(seq);
        assert_eq!(out, seq);
    }
}

#[test]
fn home_end_canonicalization() {
    // ESC [ 1 ~ -> HOME
    let out = input::canonicalize(&[0x1b, b'[', b'1', b'~']);
    assert_eq!(out, input::HOME);

    // ESC [ 4 ~ -> END
    let out = input::canonicalize(&[0x1b, b'[', b'4', b'~']);
    assert_eq!(out, input::END);

    // ESC O H -> HOME
    let out = input::canonicalize(&[0x1b, b'O', b'H']);
    assert_eq!(out, input::HOME);

    // ESC O F -> END
    let out = input::canonicalize(&[0x1b, b'O', b'F']);
    assert_eq!(out, input::END);

    // Pass-through canonical HOME/END
    let out = input::canonicalize(input::HOME);
    assert_eq!(out, input::HOME);
    let out = input::canonicalize(input::END);
    assert_eq!(out, input::END);
}

#[test]
fn page_up_down_passthrough() {
    let out = input::canonicalize(input::PAGE_UP);
    assert_eq!(out, input::PAGE_UP);
    let out = input::canonicalize(input::PAGE_DOWN);
    assert_eq!(out, input::PAGE_DOWN);
}

