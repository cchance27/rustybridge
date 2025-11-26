use crate::apps::management::types::{CredentialForm, CredentialType};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FormAction {
    Continue,
    Render,
    Submit,
    Cancel,
}

pub fn handle_form_input(form: &mut super::types::HostForm, focus: &mut usize, input: &[u8]) -> FormAction {
    let mut i = 0;
    let mut render = false;
    while i < input.len() {
        let byte = input[i];
        i += 1;
        match byte {
            0x1b => {
                if i < input.len() && input[i] == b'[' {
                    // Handle CSI
                    i += 1;
                    if i < input.len() {
                        let code = input[i];
                        i += 1;
                        match code {
                            b'A' => {
                                // Up -> previous field
                                *focus = if *focus > 0 { *focus - 1 } else { 1 };
                                render = true;
                            }
                            b'B' => {
                                // Down -> next field
                                *focus = (*focus + 1) % 2;
                                render = true;
                            }
                            b'C' => {
                                // Right
                                match *focus {
                                    0 => form.name.move_right(),
                                    1 => form.description.move_right(),
                                    _ => {}
                                }
                                render = true;
                            }
                            b'D' => {
                                // Left
                                match *focus {
                                    0 => form.name.move_left(),
                                    1 => form.description.move_left(),
                                    _ => {}
                                }
                                render = true;
                            }
                            b'H' => {
                                // Home
                                match *focus {
                                    0 => form.name.move_home(),
                                    1 => form.description.move_home(),
                                    _ => {}
                                }
                                render = true;
                            }
                            b'F' => {
                                // End
                                match *focus {
                                    0 => form.name.move_end(),
                                    1 => form.description.move_end(),
                                    _ => {}
                                }
                                render = true;
                            }
                            b'3' => {
                                // Delete key sequence: expect '~'
                                if i < input.len() && input[i] == b'~' {
                                    i += 1;
                                }
                                match *focus {
                                    0 => {
                                        let _ = form.name.delete_char();
                                    }
                                    1 => {
                                        let _ = form.description.delete_char();
                                    }
                                    _ => {}
                                }
                                render = true;
                            }
                            b'5' => {
                                // PageUp -> previous field, expect '~'
                                if i < input.len() && input[i] == b'~' {
                                    i += 1;
                                }
                                *focus = focus.saturating_sub(1);
                                if *focus > 1 {
                                    *focus = 1;
                                }
                                render = true;
                            }
                            b'6' => {
                                // PageDown -> next field, expect '~'
                                if i < input.len() && input[i] == b'~' {
                                    i += 1;
                                }
                                *focus = (*focus + 1) % 2;
                                render = true;
                            }
                            _ => {}
                        }
                    }
                } else {
                    return FormAction::Cancel;
                }
            }
            b'\t' => {
                *focus = (*focus + 1) % 2;
                render = true;
            }
            b'\r' | b'\n' => {
                return FormAction::Submit;
            }
            0x7f | 0x08 => {
                match *focus {
                    0 => {
                        let _ = form.name.pop_char();
                    }
                    1 => {
                        let _ = form.description.pop_char();
                    }
                    _ => {}
                }
                render = true;
            }
            c if (32..=126).contains(&c) => {
                let char = c as char;
                match *focus {
                    0 => form.name.push_char(char),
                    1 => form.description.push_char(char),
                    _ => {}
                }
                render = true;
            }
            _ => {}
        }
    }
    if render { FormAction::Render } else { FormAction::Continue }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CFAction {
    Continue,
    Render,
    Submit,
    Cancel,
}

pub fn handle_credential_form_input(form: &mut CredentialForm, focus: &mut usize, input: &[u8]) -> CFAction {
    let mut i = 0usize;
    let mut render = false;
    while i < input.len() {
        let b = input[i];
        i += 1;
        match b {
            0x1b => {
                if i < input.len() && input[i] == b'[' {
                    i += 1;
                    if i < input.len() {
                        let code = input[i];
                        i += 1;
                        match code {
                            b'A' => {
                                // Up
                                let is_textarea =
                                    matches!((&form.ctype, *focus), (CredentialType::SshKey, 4 | 5) | (CredentialType::Agent, 4));
                                if is_textarea {
                                    match *focus {
                                        4 => {
                                            if form.ctype == CredentialType::SshKey {
                                                form.key_value.move_up();
                                            } else {
                                                form.public_key.move_up();
                                            }
                                        }
                                        5 => {
                                            if form.ctype == CredentialType::SshKey {
                                                form.cert_value.move_up()
                                            }
                                        }
                                        _ => {}
                                    }
                                } else {
                                    let total = form.fields_len();
                                    *focus = if *focus == 0 { total - 1 } else { *focus - 1 };
                                }
                                render = true;
                            }
                            b'B' => {
                                // Down
                                let is_textarea =
                                    matches!((&form.ctype, *focus), (CredentialType::SshKey, 4 | 5) | (CredentialType::Agent, 4));
                                if is_textarea {
                                    match *focus {
                                        4 => {
                                            if form.ctype == CredentialType::SshKey {
                                                form.key_value.move_down();
                                            } else {
                                                form.public_key.move_down();
                                            }
                                        }
                                        5 => {
                                            if form.ctype == CredentialType::SshKey {
                                                form.cert_value.move_down()
                                            }
                                        }
                                        _ => {}
                                    }
                                } else {
                                    let total = form.fields_len();
                                    *focus = (*focus + 1) % total;
                                }
                                render = true;
                            }
                            b'C' => {
                                // Right
                                match *focus {
                                    0 => form.ctype = form.ctype.next(),
                                    2 => form.username_mode = form.username_mode.next(),
                                    4 if form.ctype == CredentialType::Password => form.password_required = !form.password_required,
                                    _ => match (&form.ctype, *focus) {
                                        (CredentialType::SshKey, 4) => form.key_value.move_right(),
                                        (CredentialType::SshKey, 5) => form.cert_value.move_right(),
                                        (CredentialType::Agent, 4) => form.public_key.move_right(),
                                        (CredentialType::Password, 5) => form.password.move_right(),
                                        (CredentialType::SshKey, 6) => form.passphrase.move_right(),
                                        (_, 1) => form.name.move_right(),
                                        (_, 3) => form.username.move_right(),
                                        _ => {}
                                    },
                                }
                                render = true;
                            }
                            b'D' => {
                                // Left
                                match *focus {
                                    0 => form.ctype = form.ctype.prev(),
                                    2 => form.username_mode = form.username_mode.prev(),
                                    4 if form.ctype == CredentialType::Password => form.password_required = !form.password_required,
                                    _ => match (&form.ctype, *focus) {
                                        (CredentialType::SshKey, 4) => form.key_value.move_left(),
                                        (CredentialType::SshKey, 5) => form.cert_value.move_left(),
                                        (CredentialType::Agent, 4) => form.public_key.move_left(),
                                        (CredentialType::Password, 5) => form.password.move_left(),
                                        (CredentialType::SshKey, 6) => form.passphrase.move_left(),
                                        (_, 1) => form.name.move_left(),
                                        (_, 3) => form.username.move_left(),
                                        _ => {}
                                    },
                                }
                                render = true;
                            }
                            b'H' => {
                                // Home
                                match *focus {
                                    1 => form.name.move_home(),
                                    3 => form.username.move_home(),
                                    5 if form.ctype == CredentialType::Password => form.password.move_home(),
                                    4 if form.ctype == CredentialType::SshKey => form.key_value.move_home(),
                                    5 if form.ctype == CredentialType::SshKey => form.cert_value.move_home(),
                                    6 if form.ctype == CredentialType::SshKey => form.passphrase.move_home(),
                                    4 if form.ctype == CredentialType::Agent => form.public_key.move_home(),
                                    _ => {}
                                }
                                render = true;
                            }
                            b'F' => {
                                // End
                                match *focus {
                                    1 => form.name.move_end(),
                                    3 => form.username.move_end(),
                                    5 if form.ctype == CredentialType::Password => form.password.move_end(),
                                    4 if form.ctype == CredentialType::SshKey => form.key_value.move_end(),
                                    5 if form.ctype == CredentialType::SshKey => form.cert_value.move_end(),
                                    6 if form.ctype == CredentialType::SshKey => form.passphrase.move_end(),
                                    4 if form.ctype == CredentialType::Agent => form.public_key.move_end(),
                                    _ => {}
                                }
                                render = true;
                            }
                            b'3' => {
                                if i < input.len() && input[i] == b'~' {
                                    i += 1;
                                    // Delete
                                    match *focus {
                                        1 => {
                                            let _ = form.name.delete_char();
                                        }
                                        3 => {
                                            let _ = form.username.delete_char();
                                        }
                                        5 if form.ctype == CredentialType::Password => {
                                            let _ = form.password.delete_char();
                                        }
                                        4 if form.ctype == CredentialType::SshKey => {
                                            let _ = form.key_value.delete_char();
                                        }
                                        5 if form.ctype == CredentialType::SshKey => {
                                            let _ = form.cert_value.delete_char();
                                        }
                                        6 if form.ctype == CredentialType::SshKey => {
                                            let _ = form.passphrase.delete_char();
                                        }
                                        4 if form.ctype == CredentialType::Agent => {
                                            let _ = form.public_key.delete_char();
                                        }
                                        _ => {}
                                    }
                                    render = true;
                                }
                            }
                            _ => {}
                        }
                    }
                } else {
                    return CFAction::Cancel;
                }
            }
            b'\t' => {
                let total = form.fields_len();
                *focus = (*focus + 1) % total;
                render = true;
            }
            b'\r' | b'\n' => {
                let is_textarea = matches!((&form.ctype, *focus), (CredentialType::SshKey, 4 | 5) | (CredentialType::Agent, 4));
                if is_textarea {
                    match *focus {
                        4 => {
                            if form.ctype == CredentialType::SshKey {
                                form.key_value.insert_newline();
                            } else {
                                form.public_key.insert_newline();
                            }
                        }
                        5 => {
                            if form.ctype == CredentialType::SshKey {
                                form.cert_value.insert_newline()
                            }
                        }
                        _ => {
                            unreachable!("This shouldn't happen due to is_textarea check, but added for exhaustiveness")
                        }
                    }
                    render = true;
                } else {
                    return CFAction::Submit;
                }
            }
            0x7f | 0x08 => {
                match *focus {
                    1 => {
                        let _ = form.name.pop_char();
                    }
                    3 => {
                        let _ = form.username.pop_char();
                    }
                    5 if form.ctype == CredentialType::Password => {
                        let _ = form.password.pop_char();
                    }
                    4 if form.ctype == CredentialType::SshKey => {
                        let _ = form.key_value.backspace();
                    }
                    5 if form.ctype == CredentialType::SshKey => {
                        let _ = form.cert_value.backspace();
                    }
                    6 if form.ctype == CredentialType::SshKey => {
                        let _ = form.passphrase.pop_char();
                    }
                    4 if form.ctype == CredentialType::Agent => {
                        let _ = form.public_key.backspace();
                    }
                    _ => {}
                }
                render = true;
            }
            c => {
                if c >= 32 {
                    let ch = c as char;
                    match *focus {
                        1 => form.name.push_char(ch),
                        3 => form.username.push_char(ch),
                        5 if form.ctype == CredentialType::Password => form.password.push_char(ch),
                        4 if form.ctype == CredentialType::SshKey => form.key_value.push_char(ch),
                        5 if form.ctype == CredentialType::SshKey => form.cert_value.push_char(ch),
                        6 if form.ctype == CredentialType::SshKey => form.passphrase.push_char(ch),
                        4 if form.ctype == CredentialType::Agent => form.public_key.push_char(ch),
                        _ => {}
                    }
                    render = true;
                }
            }
        }
    }
    if render { CFAction::Render } else { CFAction::Continue }
}
