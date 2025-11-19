use anyhow::{Result, anyhow};
use clap::{CommandFactory, FromArgMatches, error::ErrorKind};
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
    // Build command to intercept --help and append DB path dynamically
    let cmd = ServerArgs::command();
    let args = match cmd.try_get_matches() {
        Ok(m) => ServerArgs::from_arg_matches(&m).map_err(|e| anyhow!(e.to_string()))?,
        Err(e) => {
            if e.kind() == ErrorKind::DisplayHelp {
                // Print standard help then append our DB path hint
                e.print()?;
                println!("\nDatabase: {}", state_store::display_server_db_path());
                return Ok(());
            } else if e.kind() == ErrorKind::DisplayVersion {
                e.print()?;
                return Ok(());
            } else {
                return Err(anyhow!(e));
            }
        }
    };
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
                    // Handle --passphrase with or without value
                    let pass_opt: Option<String> = match passphrase {
                        Some(Some(p)) => Some(p),
                        Some(None) => {
                            let p = rpassword::prompt_password("Enter private key passphrase: ")?;
                            Some(p)
                        }
                        None => None,
                    };
                    let _ = server_core::create_ssh_key_credential(
                        &name,
                        Some(&username),
                        &key_data,
                        cert_data.as_deref(),
                        pass_opt.as_deref(),
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
            // Load app with real data from database (as admin)
            let app: Box<dyn tui_core::TuiApp> = match cmd {
                TuiCmd::RelaySelector => Box::new(server_core::create_relay_selector_app(None).await?),
                TuiCmd::Management => Box::new(server_core::create_management_app().await?),
            };

            run_tui(app).await?;
        }
    }
    Ok(())
}

async fn run_tui(mut app: Box<dyn tui_core::TuiApp>) -> Result<()> {
    use std::io::stdout;

    use crossterm::{
        event::{self, Event, KeyEventKind}, execute, terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode}
    };
    use ratatui::prelude::*;
    // Shared key mapping for local TUI
    use rb_cli::tui_input;
    use tui_core::{AppAction, AppSession};

    // Disable logging to prevent interference with TUI
    ssh_core::logging::disable_logging();

    enable_raw_mode()?;
    let mut stdout = stdout();
    execute!(stdout, EnterAlternateScreen)?;

    loop {
        let backend = CrosstermBackend::new(std::io::stdout());
        let mut session = AppSession::new(app, backend).map_err(|e: tui_core::TuiError| anyhow::anyhow!(e))?;
        let mut next_app_name: Option<String> = None;
        let mut next_mgmt_tab: Option<usize> = None;

        loop {
            session.render().map_err(|e: tui_core::TuiError| anyhow::anyhow!(e))?;

            if event::poll(std::time::Duration::from_millis(100))?
                && let Event::Key(key) = event::read()?
                && key.kind == KeyEventKind::Press
            {
                // Map crossterm keys to canonical TUI bytes
                let bytes = tui_input::map_key_to_bytes(&key);

                if bytes.is_none() {
                    continue;
                }
                let canonical = tui_core::input::canonicalize(&bytes.unwrap());
                let action = session
                    .handle_input(&canonical)
                    .map_err(|e: tui_core::TuiError| anyhow::anyhow!(e))?;
                match action {
                    AppAction::Exit => {
                        next_app_name = None;
                        break;
                    }
                    AppAction::SwitchTo(name) => {
                        next_app_name = Some(name);
                        break;
                    }
                    AppAction::ConnectToRelay { name, .. } => {
                        // Exit TUI and connect to the relay
                        disable_raw_mode()?;
                        execute!(stdout, LeaveAlternateScreen)?;

                        // Give immediate feedback so it doesn't feel frozen
                        use std::io::Write as _;
                        println!("Connecting via proxy to {}...", name);
                        std::io::stdout().flush().ok();

                        // Best effort: print endpoint once available (does not block the initial feedback)
                        if let Ok(handle) = state_store::server_db().await {
                            let _ = state_store::migrate_server(&handle).await;
                            let pool = handle.into_pool();
                            if let Ok(Some(h)) = state_store::fetch_relay_host_by_name(&pool, &name).await {
                                println!("Endpoint: {}:{}", h.ip, h.port);
                            }
                        }

                        let user = std::env::var("USER").unwrap_or_else(|_| "root".to_string());

                        if let Err(e) = server_core::connect_to_relay_local(&name, &user).await {
                            eprintln!("Connection failed: {}", e);
                        }
                        return Ok(());
                    }
                    AppAction::AddRelay(_)
                    | AppAction::UpdateRelay(_)
                    | AppAction::DeleteRelay(_)
                    | AppAction::AddCredential(_)
                    | AppAction::DeleteCredential(_)
                    | AppAction::UnassignCredential(_)
                    | AppAction::AssignCredential { .. } => {
                        let cloned = action.clone();
                        let _ = server_core::handle_management_action_with_flash(cloned).await;
                        // Reload Management app data
                        next_app_name = Some("Management".to_string());
                        // Keep user on the relevant tab after action
                        next_mgmt_tab = Some(match action {
                            AppAction::AddCredential(_) | AppAction::DeleteCredential(_) => 1,
                            _ => 0,
                        });
                        break;
                    }
                    _ => {}
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
            // Load app with real data from database
            app = match name.as_str() {
                "Management" => {
                    let tab = next_mgmt_tab.unwrap_or(0);
                    Box::new(server_core::create_management_app_with_tab(tab).await?)
                }
                _ => Box::new(server_core::create_relay_selector_app(None).await?), // None = admin
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
