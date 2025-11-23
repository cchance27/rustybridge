use anyhow::{Result, anyhow};
use clap::{CommandFactory, FromArgMatches, error::ErrorKind};
use crossterm::{
    event::{self, Event, KeyEventKind}, execute, terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode}
};
use ratatui::prelude::*;
use rb_cli::{
    init_tracing, server_cli::{
        CredsCmd, CredsCreateCmd, GroupMembersCmd, GroupsCmd, HostsAccessCmd, HostsCmd, HostsCredsCmd, HostsOptionsCmd, RolesCmd, SecretsCmd, ServerArgs, ServerSubcommand, UsersCmd
    }, tui_input
};
use rb_types::web::PrincipalKind;
use rb_web::run_web_server;
use server_core::{
    add_group, add_relay_host, add_role_claim, add_user, add_user_to_group_server, assign_credential, assign_role, create_agent_credential, create_password_credential, create_role, delete_credential, delete_role, grant_relay_access, list_access, list_credentials, list_group_members_server, list_groups, list_hosts, list_options, list_roles, list_user_groups_server, list_users, refresh_target_hostkey, remove_group, remove_role_claim, remove_user, remove_user_from_group_server, revoke_relay_access, revoke_role, rotate_secrets_key, run_ssh_server, set_relay_option, unassign_credential, unset_relay_option
};
use tui_core::{AppAction, AppSession};

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();

    // Migrate server DB on Startup
    let handle = state_store::server_db().await?;
    state_store::migrate_server(&handle).await?;

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
    let web_config = args.to_web_config()?;

    match args.cmd {
        None => {
            if let Some(web_cfg) = web_config {
                let server_cfg = args.to_run_config();

                let mut server_task = tokio::spawn(async move { run_ssh_server(server_cfg).await });
                let mut web_task = tokio::spawn(async move { run_web_server(web_cfg, rb_web::app_root::app_root).await });

                tokio::select! {
                    res = &mut server_task => {
                        web_task.abort();
                        res??;
                    }
                    res = &mut web_task => {
                        // If the web server exits (error or shutdown) bring down SSH too
                        server_task.abort();
                        res??;
                    }
                }
            } else {
                run_ssh_server(args.to_run_config()).await?;
            }
        }
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
                HostsOptionsCmd::Set { name, key, value } => set_relay_option(&name, &key, &value, true).await?,
                HostsOptionsCmd::Unset { name, key } => unset_relay_option(&name, &key).await?,
            },
            HostsCmd::Access(sub) => match sub {
                HostsAccessCmd::Grant { name, user, group } => {
                    if let Some(u) = user {
                        grant_relay_access(&name, PrincipalKind::User, &u).await?
                    } else if let Some(g) = group {
                        grant_relay_access(&name, PrincipalKind::Group, &g).await?
                    }
                }
                HostsAccessCmd::Revoke { name, user, group } => {
                    if let Some(u) = user {
                        revoke_relay_access(&name, PrincipalKind::User, &u).await?
                    } else if let Some(g) = group {
                        revoke_relay_access(&name, PrincipalKind::Group, &g).await?
                    }
                }
                HostsAccessCmd::List { name } => {
                    for p in list_access(&name).await? {
                        let kind = match p.kind {
                            PrincipalKind::User => "user",
                            PrincipalKind::Group => "group",
                            PrincipalKind::Other => "other",
                        };
                        println!("{} {}", kind, p.name);
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
            UsersCmd::AssignRole { user, role } => assign_role(&user, &role).await?,
            UsersCmd::RevokeRole { user, role } => revoke_role(&user, &role).await?,
        },
        Some(ServerSubcommand::Groups { cmd }) => match cmd {
            GroupsCmd::Add { group } => add_group(&group).await?,
            GroupsCmd::Remove { group } => remove_group(&group).await?,
            GroupsCmd::List => {
                for g in list_groups().await? {
                    println!("{}", g);
                }
            }
            GroupsCmd::Members { cmd } => match cmd {
                GroupMembersCmd::Add { group, user } => add_user_to_group_server(&user, &group).await?,
                GroupMembersCmd::Remove { group, user } => remove_user_from_group_server(&user, &group).await?,
                GroupMembersCmd::List { group } => {
                    for u in list_group_members_server(&group).await? {
                        println!("{}", u);
                    }
                }
            },
            GroupsCmd::UserGroups { user } => {
                for g in list_user_groups_server(&user).await? {
                    println!("{}", g);
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
                for (_id, name, kind, _meta) in list_credentials().await? {
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
                TuiCmd::Management => Box::new(server_core::create_management_app(None).await?),
            };

            run_tui(app).await?;
        }
        Some(ServerSubcommand::Roles { cmd }) => match cmd {
            RolesCmd::Create { name, description } => create_role(&name, description.as_deref()).await?,
            RolesCmd::Delete { name } => delete_role(&name).await?,
            RolesCmd::List => {
                for r in list_roles().await? {
                    println!("{} ({})", r.name, r.description.unwrap_or_default());
                }
            }
            RolesCmd::AddClaim { role, claim } => add_role_claim(&role, &claim).await?,
            RolesCmd::RemoveClaim { role, claim } => remove_role_claim(&role, &claim).await?,
        },
    }
    Ok(())
}

async fn run_tui(app: Box<dyn tui_core::TuiApp>) -> Result<()> {
    ssh_core::logging::disable_logging();

    enable_raw_mode()?;
    execute!(std::io::stdout(), EnterAlternateScreen)?;
    let mut in_alt_screen = true;

    let backend = CrosstermBackend::new(std::io::stdout());
    let mut session = AppSession::new(app, backend).map_err(|e: tui_core::TuiError| anyhow::anyhow!(e))?;

    loop {
        session.render().map_err(|e: tui_core::TuiError| anyhow::anyhow!(e))?;

        if event::poll(std::time::Duration::from_millis(100))?
            && let Event::Key(key) = event::read()?
            && key.kind == KeyEventKind::Press
            && let Some(bytes) = tui_input::map_key_to_bytes(&key)
        {
            let canonical = tui_core::input::canonicalize(&bytes);
            let action = session
                .handle_input(&canonical)
                .map_err(|e: tui_core::TuiError| anyhow::anyhow!(e))?;
            if handle_local_action(&mut session, action, &mut in_alt_screen).await? {
                break;
            }
            continue;
        }

        let action = session.tick().map_err(|e: tui_core::TuiError| anyhow::anyhow!(e))?;
        if handle_local_action(&mut session, action, &mut in_alt_screen).await? {
            break;
        }

        // No background reloads; status and fetches are session-scoped
    }

    if in_alt_screen {
        disable_raw_mode()?;
        execute!(std::io::stdout(), LeaveAlternateScreen)?;
    }
    Ok(())
}

async fn handle_local_action(
    session: &mut AppSession<CrosstermBackend<std::io::Stdout>>,
    action: AppAction,
    in_alt_screen: &mut bool,
) -> Result<bool> {
    use AppAction::*;
    match action {
        Exit => Ok(true),
        Render | Continue => Ok(false),
        SwitchTo(name) => {
            let app = build_app_for_local(&name, None).await?;
            session.set_app(app).map_err(|e: tui_core::TuiError| anyhow::anyhow!(e))?;
            Ok(false)
        }
        ConnectToRelay { name, .. } => {
            use std::io::Write as _;
            disable_raw_mode()?;
            execute!(std::io::stdout(), LeaveAlternateScreen)?;
            *in_alt_screen = false;
            println!("Connecting via proxy to {}...", name);
            std::io::stdout().flush().ok();
            if let Ok(handle) = state_store::server_db().await {
                let pool = handle.into_pool();
                if let Ok(Some(h)) = state_store::fetch_relay_host_by_name(&pool, &name).await {
                    println!("Endpoint: {}:{}", h.ip, h.port);
                }
            }
            let user = std::env::var("USER").unwrap_or_else(|_| "root".to_string());
            if let Err(e) = server_core::connect_to_relay_local(&name, &user).await {
                eprintln!("Connection failed: {}", e);
            }
            Ok(true)
        }
        FetchHostkey { id, name } => {
            // Per-session status message
            session.set_status(Some(tui_core::app::StatusLine {
                text: format!("Fetching host key for '{}'...", name),
                kind: tui_core::app::StatusKind::Info,
            }));
            session.render().map_err(|e: tui_core::TuiError| anyhow::anyhow!(e))?;
            // Perform the fetch inline
            let action = tui_core::AppAction::FetchHostkey { id, name: name.clone() };
            match server_core::handle_management_action(action).await {
                Ok(Some(AppAction::ReviewHostkey(review))) => {
                    // Reload with the review data
                    let app2 = server_core::create_management_app_with_tab(0, Some(review)).await?;
                    session
                        .set_app(Box::new(app2))
                        .map_err(|e: tui_core::TuiError| anyhow::anyhow!(e))?;
                }
                Ok(Some(AppAction::Error(msg))) => {
                    session.set_status(Some(tui_core::app::StatusLine {
                        text: msg,
                        kind: tui_core::app::StatusKind::Error,
                    }));
                }
                Ok(_) => {
                    // Reload without review
                    let app2 = build_app_for_local("Management", Some(0)).await?;
                    session.set_app(app2).map_err(|e: tui_core::TuiError| anyhow::anyhow!(e))?;
                }
                Err(e) => {
                    tracing::warn!("hostkey fetch failed: {}", e);
                    session.set_status(Some(tui_core::app::StatusLine {
                        text: format!("Hostkey fetch failed: {}", e),
                        kind: tui_core::app::StatusKind::Error,
                    }));
                }
            }
            Ok(false)
        }
        add @ (AddRelay(_)
        | UpdateRelay(_)
        | DeleteRelay(_)
        | AddCredential(_)
        | DeleteCredential(_)
        | UnassignCredential(_)
        | AssignCredential { .. }
        | StoreHostkey { .. }
        | CancelHostkey { .. }) => {
            let tab = if matches!(add, AddCredential(_) | DeleteCredential(_)) {
                1
            } else {
                0
            };
            let res = server_core::handle_management_action(add.clone()).await;
            let app = build_app_for_local("Management", Some(tab)).await?;
            session.set_app(app).map_err(|e: tui_core::TuiError| anyhow::anyhow!(e))?;
            match res {
                Ok(_) => {
                    if let AppAction::StoreHostkey { name, .. } = add {
                        session.set_status(Some(tui_core::app::StatusLine {
                            text: format!("Stored host key for '{}'", name),
                            kind: tui_core::app::StatusKind::Success,
                        }));
                    }
                }
                Err(e) => {
                    tracing::warn!("failed to apply management action: {}", e);
                    let msg = server_core::format_action_error(&add, &e);
                    session.set_status(Some(tui_core::app::StatusLine {
                        text: msg,
                        kind: tui_core::app::StatusKind::Error,
                    }));
                }
            }
            session.render().map_err(|e: tui_core::TuiError| anyhow::anyhow!(e))?;
            Ok(false)
        }
        Error(msg) => {
            session.set_status(Some(tui_core::app::StatusLine {
                text: msg,
                kind: tui_core::app::StatusKind::Error,
            }));
            Ok(false)
        }
        ReviewHostkey(review) => {
            // Reload management app with the review
            let app = server_core::create_management_app_with_tab(0, Some(review)).await?;
            session.set_app(Box::new(app)).map_err(|e: tui_core::TuiError| anyhow::anyhow!(e))?;
            Ok(false)
        }
    }
}

async fn build_app_for_local(name: &str, tab: Option<usize>) -> anyhow::Result<Box<dyn tui_core::TuiApp>> {
    let app = server_core::create_app_by_name(None, name, tab).await?;
    Ok(app)
}
