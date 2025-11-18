use anyhow::{Result, anyhow};
use clap::Parser;
use rb_cli::{
    init_tracing, server_cli::{
        CredsCmd, CredsCreateCmd, HostsAccessCmd, HostsCmd, HostsCredsCmd, HostsOptionsCmd, SecretsCmd, ServerArgs, ServerSubcommand, UsersCmd
    }
};
use server_core::{
    add_relay_host, add_user, assign_credential, create_agent_credential, create_password_credential, delete_credential, grant_relay_access, list_access, list_credentials, list_hosts, list_options, list_users, refresh_target_hostkey, remove_user, revoke_relay_access, rotate_secrets_key, run_server, set_relay_option, unassign_credential, unset_relay_option
};

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();
    let args = ServerArgs::parse();
    match args.cmd {
        None => run_server(args.to_run_config()).await?,
        Some(ServerSubcommand::Hosts { cmd }) => match cmd {
            HostsCmd::Add { name, endpoint } => add_relay_host(&endpoint, &name).await?,
            HostsCmd::List => {
                for h in list_hosts().await? {
                    println!("{} {}:{}", h.name, h.ip, h.port);
                }
            }
            HostsCmd::Delete { name } => {
                server_core::delete_relay_host(&name).await?;
            }
            HostsCmd::Options(sub) => match sub {
                HostsOptionsCmd::List { name } => {
                    for (k, v) in list_options(&name).await? {
                        println!("{}={}", k, v);
                    }
                }
                HostsOptionsCmd::Set { name, key, value } => set_relay_option(&name, &key, &value).await?,
                HostsOptionsCmd::Unset { name, key } => unset_relay_option(&name, &key).await?,
            },
            HostsCmd::Access(sub) => match sub {
                HostsAccessCmd::Grant { name, user } => grant_relay_access(&name, &user).await?,
                HostsAccessCmd::Revoke { name, user } => revoke_relay_access(&name, &user).await?,
                HostsAccessCmd::List { name } => {
                    for u in list_access(&name).await? {
                        println!("{}", u);
                    }
                }
            },
            HostsCmd::RefreshHostkey { name } => refresh_target_hostkey(&name).await?,
            HostsCmd::Creds(sub) => match sub {
                HostsCredsCmd::Assign { name, cred_name } => assign_credential(&name, &cred_name).await?,
                HostsCredsCmd::Unassign { name } => unassign_credential(&name).await?,
            },
        },
        Some(ServerSubcommand::Users { cmd }) => match cmd {
            UsersCmd::Add { user, password } => {
                let pass = if let Some(p) = password {
                    p
                } else {
                    rpassword::prompt_password(format!("Enter password for {user}: "))?
                };
                add_user(&user, &pass).await?;
            }
            UsersCmd::Remove { user } => remove_user(&user).await?,
            UsersCmd::List => {
                for u in list_users().await? {
                    println!("{}", u);
                }
            }
        },
        Some(ServerSubcommand::Creds { cmd }) => match cmd {
            CredsCmd::Create(kind) => match kind {
                CredsCreateCmd::Password { name, username, value } => {
                    let pass = if let Some(v) = value {
                        v
                    } else {
                        rpassword::prompt_password(format!("Enter credential password for {name}: "))?
                    };
                    let _ = create_password_credential(&name, Some(&username), &pass).await?;
                }
                CredsCreateCmd::SshKey {
                    name,
                    username,
                    key_file,
                    value,
                    cert_file,
                    passphrase,
                } => {
                    let key_data = if let Some(v) = value {
                        v
                    } else if let Some(path) = key_file {
                        std::fs::read_to_string(&path)?
                    } else {
                        return Err(anyhow!("--key-file or --value is required for ssh-key credentials"));
                    };
                    let cert_data = if let Some(cp) = cert_file {
                        Some(std::fs::read_to_string(&cp)?)
                    } else {
                        None
                    };
                    let _ = server_core::create_ssh_key_credential(
                        &name,
                        Some(&username),
                        &key_data,
                        cert_data.as_deref(),
                        passphrase.as_deref(),
                    )
                    .await?;
                }
                CredsCreateCmd::Agent {
                    name,
                    username,
                    pubkey_file,
                    value,
                } => {
                    let pubkey = if let Some(v) = value {
                        v
                    } else if let Some(path) = pubkey_file {
                        std::fs::read_to_string(&path)?
                    } else {
                        return Err(anyhow!("--pubkey-file or --value is required for agent credentials"));
                    };
                    let _ = create_agent_credential(&name, Some(&username), &pubkey).await?;
                }
            },
            CredsCmd::Delete { name, force: _ } => {
                // force not yet used; guard already enforced in server-core
                delete_credential(&name).await?;
            }
            CredsCmd::List => {
                for (_id, name, kind) in list_credentials().await? {
                    println!("{} {}", name, kind);
                }
            }
        },
        Some(ServerSubcommand::Secrets {
            cmd: SecretsCmd::RotateKey,
        }) => {
            println!("Rotate server secrets will re-encrypt all credentials and relay options.");
            let old = rpassword::prompt_password("Enter CURRENT secrets key or passphrase: ")?;
            let new = rpassword::prompt_password("Enter NEW secrets key or passphrase: ")?;
            rotate_secrets_key(&old, &new).await?;
            println!(
                "Secrets rotation complete. Set RB_SERVER_SECRETS_KEY (base64 32B) or RB_SERVER_SECRETS_PASSPHRASE to the NEW value and restart rb-server."
            );
        }
        Some(ServerSubcommand::Tui { cmd }) => {
            use rb_cli::server_cli::TuiCmd;
            let app: Box<dyn tui_core::TuiApp> = match cmd {
                TuiCmd::RelaySelector => {
                    use tui_core::apps::relay_selector::RelayItem;
                    let relays = vec![
                        RelayItem { name: "us-east-1".into(), description: "Primary US Relay".into(), id: 1 },
                        RelayItem { name: "eu-central-1".into(), description: "Frankfurt Relay".into(), id: 2 },
                    ];
                    Box::new(tui_core::apps::RelaySelectorApp::new(relays))
                }
                TuiCmd::Management => Box::new(tui_core::apps::ManagementApp::new()),
            };
            
            run_tui(app).await?;
        }
    }
    Ok(())
}

async fn run_tui(mut app: Box<dyn tui_core::TuiApp>) -> Result<()> {
    use crossterm::{
        event::{self, Event, KeyCode, KeyEventKind},
        execute,
        terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
    };
    use ratatui::prelude::*;
    use std::io::stdout;
    use tui_core::{AppSession, AppAction};

    enable_raw_mode()?;
    let mut stdout = stdout();
    execute!(stdout, EnterAlternateScreen)?;
    
    loop {
        let backend = CrosstermBackend::new(std::io::stdout());
        let mut session = AppSession::new(app, backend).map_err(|e: tui_core::TuiError| anyhow::anyhow!(e))?;
        let mut next_app_name: Option<String> = None;
        
        loop {
            session.render().map_err(|e: tui_core::TuiError| anyhow::anyhow!(e))?;
            
            if event::poll(std::time::Duration::from_millis(100))? 
                && let Event::Key(key) = event::read()? 
                && key.kind == KeyEventKind::Press {
                let mut bytes = Vec::new();
                match key.code {
                    KeyCode::Char(c) => bytes.push(c as u8),
                    KeyCode::Enter => bytes.push(b'\n'),
                    KeyCode::Backspace => bytes.push(0x7f),
                    KeyCode::Esc => bytes.push(0x1b),
                    KeyCode::Up => bytes.extend_from_slice(b"\x1b[A"),
                    KeyCode::Down => bytes.extend_from_slice(b"\x1b[B"),
                    KeyCode::Right => bytes.extend_from_slice(b"\x1b[C"),
                    KeyCode::Left => bytes.extend_from_slice(b"\x1b[D"),
                    KeyCode::Tab => bytes.push(b'\t'),
                    _ => {}
                }
                
                if !bytes.is_empty() {
                    let action = session.handle_input(&bytes).map_err(|e: tui_core::TuiError| anyhow::anyhow!(e))?;
                    match action {
                        AppAction::Exit => break,
                        AppAction::SwitchTo(name) => {
                            next_app_name = Some(name);
                            break;
                        }
                        _ => {}
                    }
                }
            }
            
            let action = session.tick().map_err(|e: tui_core::TuiError| anyhow::anyhow!(e))?;
            match action {
                AppAction::Exit => break,
                AppAction::SwitchTo(name) => {
                    next_app_name = Some(name);
                    break;
                }
                _ => {}
            }
        }

        if let Some(name) = next_app_name {
            use tui_core::apps::{ManagementApp, RelaySelectorApp, RelayItem};
            app = match name.as_str() {
                "RelaySelector" => {
                    let relays = vec![
                        RelayItem { name: "us-east-1".into(), description: "Primary US Relay".into(), id: 1 },
                        RelayItem { name: "eu-central-1".into(), description: "Frankfurt Relay".into(), id: 2 },
                    ];
                    Box::new(RelaySelectorApp::new(relays))
                }
                "Management" => Box::new(ManagementApp::new()),
                _ => {
                    let relays = vec![
                        RelayItem { name: "us-east-1".into(), description: "Primary US Relay".into(), id: 1 },
                        RelayItem { name: "eu-central-1".into(), description: "Frankfurt Relay".into(), id: 2 },
                    ];
                    Box::new(RelaySelectorApp::new(relays))
                }
            };
            // Clear screen for next app
            execute!(stdout, crossterm::terminal::Clear(crossterm::terminal::ClearType::All))?;
        } else {
            break;
        }
    }

    disable_raw_mode()?;
    execute!(std::io::stdout(), LeaveAlternateScreen)?;
    Ok(())
}
