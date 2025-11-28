use anyhow::{Result, anyhow};
use clap::{CommandFactory, FromArgMatches, error::ErrorKind};
use crossterm::{
    event::{self, Event, KeyEventKind}, execute, terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode}
};
use ratatui::prelude::*;
use rb_cli::{
    init_tracing, server_cli::{
        CredsCmd, CredsCreateCmd, GroupMembersCmd, GroupsCmd, HostsAccessCmd, HostsCmd, HostsCredsCmd, HostsOptionsCmd, RolesCmd, SecretsCmd, ServerArgs, ServerSubcommand, UsersCmd, WebCmd
    }, tui_input
};
use rb_types::access::PrincipalKind;
use rb_web::run_web_server;
use server_core::{
    add_group, add_relay_host, add_user, add_user_public_key, assign_credential_by_ids, create_agent_credential, create_password_credential, delete_credential_by_id, delete_relay_host_by_id, delete_user_public_key, grant_relay_access_by_id, list_access_by_id, list_credentials, list_group_members_server, list_groups, list_hosts, list_options_by_id, list_user_groups_server, list_user_public_keys, refresh_target_hostkey, remove_group_by_id, remove_user_by_id, revoke_relay_access_by_id, rotate_secrets_key, run_ssh_server, set_relay_option_by_id, unassign_credential_by_id, unset_relay_option_by_id
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
                let db = state_store::server_db().await?;
                let pool = db.into_pool();
                let host = state_store::fetch_relay_host_by_name(&pool, &name)
                    .await?
                    .ok_or_else(|| anyhow!("Relay host '{}' not found", name))?;
                delete_relay_host_by_id(host.id).await?;
            }
            HostsCmd::Options(sub) => match sub {
                HostsOptionsCmd::List { name } => {
                    let db = state_store::server_db().await?;
                    let pool = db.into_pool();
                    let host = state_store::fetch_relay_host_by_name(&pool, &name)
                        .await?
                        .ok_or_else(|| anyhow!("Relay host '{}' not found", name))?;
                    for (k, v) in list_options_by_id(host.id).await? {
                        println!("{}={}", k, v);
                    }
                }
                HostsOptionsCmd::Set { name, key, value } => {
                    let db = state_store::server_db().await?;
                    let pool = db.into_pool();
                    let host = state_store::fetch_relay_host_by_name(&pool, &name)
                        .await?
                        .ok_or_else(|| anyhow!("Relay host '{}' not found", name))?;
                    set_relay_option_by_id(host.id, &key, &value, true).await?;
                }
                HostsOptionsCmd::Unset { name, key } => {
                    let db = state_store::server_db().await?;
                    let pool = db.into_pool();
                    let host = state_store::fetch_relay_host_by_name(&pool, &name)
                        .await?
                        .ok_or_else(|| anyhow!("Relay host '{}' not found", name))?;
                    unset_relay_option_by_id(host.id, &key).await?;
                }
            },
            HostsCmd::Access(sub) => match sub {
                HostsAccessCmd::Grant { name, user, group } => {
                    let db = state_store::server_db().await?;
                    let pool = db.into_pool();
                    let host = state_store::fetch_relay_host_by_name(&pool, &name)
                        .await?
                        .ok_or_else(|| anyhow!("Relay host '{}' not found", name))?;

                    if let Some(u) = user {
                        // Verify user exists
                        let user_id = state_store::fetch_user_id_by_name(&pool, &u)
                            .await?
                            .ok_or_else(|| anyhow!("User '{}' not found", u))?;
                        grant_relay_access_by_id(host.id, PrincipalKind::User, user_id).await?
                    } else if let Some(g) = group {
                        // Verify group exists
                        let group_id = state_store::fetch_group_id_by_name(&pool, &g)
                            .await?
                            .ok_or_else(|| anyhow!("Group '{}' not found", g))?;
                        grant_relay_access_by_id(host.id, PrincipalKind::Group, group_id).await?
                    }
                }
                HostsAccessCmd::Revoke { name, user, group } => {
                    let db = state_store::server_db().await?;
                    let pool = db.into_pool();
                    let host = state_store::fetch_relay_host_by_name(&pool, &name)
                        .await?
                        .ok_or_else(|| anyhow!("Relay host '{}' not found", name))?;

                    if let Some(u) = user {
                        // Verify user exists (optional but good practice)
                        let user_id = state_store::fetch_user_id_by_name(&pool, &u)
                            .await?
                            .ok_or_else(|| anyhow!("User '{}' not found", u))?;
                        revoke_relay_access_by_id(host.id, PrincipalKind::User, user_id).await?
                    } else if let Some(g) = group {
                        // Verify group exists
                        let group_id = state_store::fetch_group_id_by_name(&pool, &g)
                            .await?
                            .ok_or_else(|| anyhow!("Group '{}' not found", g))?;
                        revoke_relay_access_by_id(host.id, PrincipalKind::Group, group_id).await?
                    }
                }
                HostsAccessCmd::List { name } => {
                    let db = state_store::server_db().await?;
                    let pool = db.into_pool();
                    let host = state_store::fetch_relay_host_by_name(&pool, &name)
                        .await?
                        .ok_or_else(|| anyhow!("Relay host '{}' not found", name))?;

                    for p in list_access_by_id(host.id).await? {
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
                HostsCredsCmd::Assign { name, cred_name } => {
                    let db = state_store::server_db().await?;
                    let pool = db.into_pool();
                    let host = state_store::fetch_relay_host_by_name(&pool, &name)
                        .await?
                        .ok_or_else(|| anyhow!("Relay host '{}' not found", name))?;
                    let cred = state_store::get_relay_credential_by_name(&pool, &cred_name)
                        .await?
                        .ok_or_else(|| anyhow!("Credential '{}' not found", cred_name))?;

                    assign_credential_by_ids(host.id, cred.id).await?
                }
                HostsCredsCmd::Unassign { name } => {
                    let db = state_store::server_db().await?;
                    let pool = db.into_pool();
                    let host = state_store::fetch_relay_host_by_name(&pool, &name)
                        .await?
                        .ok_or_else(|| anyhow!("Relay host '{}' not found", name))?;

                    unassign_credential_by_id(host.id).await?
                }
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
            UsersCmd::AddPubkey {
                user,
                key_file,
                public_key,
                comment,
            } => {
                let key_data = if let Some(k) = public_key {
                    k
                } else if let Some(path) = key_file {
                    std::fs::read_to_string(&path)?.trim().to_string()
                } else {
                    return Err(anyhow!("public key is required (pass as positional or --key-file)"));
                };

                let id = add_user_public_key(&user, &key_data, comment.as_deref()).await?;
                println!("added public key {} for {}", id, user);
            }
            UsersCmd::ListPubkeys { user } => {
                let keys = list_user_public_keys(&user).await?;
                if keys.is_empty() {
                    println!("no public keys found for {}", user);
                } else {
                    for (id, key, comment, created_at) in keys {
                        // Show a short fingerprint-like suffix for readability
                        let suffix = key.split_whitespace().last().unwrap_or("");
                        println!("{} {} {} {}", id, created_at, suffix, comment.unwrap_or_default());
                    }
                }
            }
            UsersCmd::RemovePubkey { user, key_id } => {
                delete_user_public_key(&user, key_id).await?;
                println!("removed public key {} for {}", key_id, user);
            }
            UsersCmd::Remove { user } => {
                // Convert username to ID
                let db = state_store::server_db().await?;
                let pool = db.into_pool();
                let user_id = state_store::fetch_user_id_by_name(&pool, &user)
                    .await?
                    .ok_or_else(|| anyhow!("User '{}' not found", user))?;
                remove_user_by_id(user_id).await?;
            }
            UsersCmd::List => {
                let db = state_store::server_db().await?;
                let pool = db.into_pool();
                for u in state_store::list_usernames(&pool).await? {
                    println!("{}", u);
                }
            }
            UsersCmd::AssignRole { user, role } => {
                let db = state_store::server_db().await?;
                let pool = db.into_pool();
                let user_id = state_store::fetch_user_id_by_name(&pool, &user)
                    .await?
                    .ok_or_else(|| anyhow!("User '{}' not found", user))?;
                let role_id = state_store::fetch_role_id_by_name(&pool, &role)
                    .await?
                    .ok_or_else(|| anyhow!("Role '{}' not found", role))?;

                state_store::assign_role_to_user_by_ids(&pool, user_id, role_id).await?
            }
            UsersCmd::RevokeRole { user, role } => {
                let db = state_store::server_db().await?;
                let pool = db.into_pool();
                let user_id = state_store::fetch_user_id_by_name(&pool, &user)
                    .await?
                    .ok_or_else(|| anyhow!("User '{}' not found", user))?;
                let role_id = state_store::fetch_role_id_by_name(&pool, &role)
                    .await?
                    .ok_or_else(|| anyhow!("Role '{}' not found", role))?;

                let mut conn = pool.acquire().await?;
                state_store::revoke_role_from_user_by_ids(&mut conn, user_id, role_id).await?
            }
        },
        Some(ServerSubcommand::Groups { cmd }) => match cmd {
            GroupsCmd::Add { group } => add_group(&group).await?,
            GroupsCmd::Remove { group } => {
                // Convert group name to ID
                let db = state_store::server_db().await?;
                let pool = db.into_pool();
                let group_id = state_store::fetch_group_id_by_name(&pool, &group)
                    .await?
                    .ok_or_else(|| anyhow!("Group '{}' not found", group))?;
                remove_group_by_id(group_id).await?;
            }
            GroupsCmd::List => {
                for g in list_groups().await? {
                    println!("{}", g);
                }
            }
            GroupsCmd::Members { cmd } => match cmd {
                GroupMembersCmd::Add { group, user } => {
                    let db = state_store::server_db().await?;
                    let pool = db.into_pool();
                    let group_id = state_store::fetch_group_id_by_name(&pool, &group)
                        .await?
                        .ok_or_else(|| anyhow!("Group '{}' not found", group))?;
                    let user_id = state_store::fetch_user_id_by_name(&pool, &user)
                        .await?
                        .ok_or_else(|| anyhow!("User '{}' not found", user))?;

                    state_store::add_user_to_group_by_ids(&pool, user_id, group_id).await?
                }
                GroupMembersCmd::Remove { group, user } => {
                    let db = state_store::server_db().await?;
                    let pool = db.into_pool();
                    let group_id = state_store::fetch_group_id_by_name(&pool, &group)
                        .await?
                        .ok_or_else(|| anyhow!("Group '{}' not found", group))?;
                    let user_id = state_store::fetch_user_id_by_name(&pool, &user)
                        .await?
                        .ok_or_else(|| anyhow!("User '{}' not found", user))?;

                    state_store::remove_user_from_group_by_ids(&pool, user_id, group_id).await?
                }
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
                    let _ = create_password_credential(&name, Some(&username), &pass, "fixed", true).await?;
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
                        "fixed",
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
                    let _ = create_agent_credential(&name, Some(&username), &pubkey, "fixed").await?;
                }
            },
            CredsCmd::Delete { name, force: _ } => {
                let db = state_store::server_db().await?;
                let pool = db.into_pool();
                let cred = state_store::get_relay_credential_by_name(&pool, &name)
                    .await?
                    .ok_or_else(|| anyhow!("Credential '{}' not found", name))?;
                // force not yet used; guard already enforced in server-core
                delete_credential_by_id(cred.id).await?;
            }
            CredsCmd::List => {
                for (_id, name, kind, _meta, _username_mode, _password_required) in list_credentials().await? {
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
            RolesCmd::Create { name, description } => {
                let db = state_store::server_db().await?;
                let pool = db.into_pool();
                state_store::create_role(&pool, &name, description.as_deref()).await?;
            }
            RolesCmd::Delete { name } => {
                // Convert role name to ID
                let db = state_store::server_db().await?;
                let pool = db.into_pool();
                let role_id = state_store::fetch_role_id_by_name(&pool, &name)
                    .await?
                    .ok_or_else(|| anyhow!("Role '{}' not found", name))?;
                state_store::delete_role_by_id(&pool, role_id).await?;
            }
            RolesCmd::List => {
                let db = state_store::server_db().await?;
                let pool = db.into_pool();
                for r in state_store::list_roles(&pool).await? {
                    println!("{} - {}", r.name, r.description.unwrap_or_default());
                }
            }
            RolesCmd::AddClaim { role, claim } => {
                let db = state_store::server_db().await?;
                let pool = db.into_pool();
                let role_id = state_store::fetch_role_id_by_name(&pool, &role)
                    .await?
                    .ok_or_else(|| anyhow!("Role '{}' not found", role))?;

                state_store::add_claim_to_role_by_id(&pool, role_id, &claim).await?
            }
            RolesCmd::RemoveClaim { role, claim } => {
                let db = state_store::server_db().await?;
                let pool = db.into_pool();
                let role_id = state_store::fetch_role_id_by_name(&pool, &role)
                    .await?
                    .ok_or_else(|| anyhow!("Role '{}' not found", role))?;

                state_store::remove_claim_from_role_by_id(&pool, role_id, &claim).await?
            }
        },
        Some(ServerSubcommand::Web { cmd }) => match cmd {
            WebCmd::Set { key, value } => {
                use rb_cli::server_cli::WebOptionKey;
                let (stored_key, label, is_secret) = match key {
                    WebOptionKey::ServerUrl => ("web_base_url", "server_url", false),
                    WebOptionKey::OidcIssuerUrl => ("oidc_issuer_url", "oidc_issuer_url", false),
                    WebOptionKey::OidcClientId => ("oidc_client_id", "oidc_client_id", false),
                    WebOptionKey::OidcClientSecret => ("oidc_client_secret", "oidc_client_secret", true),
                    WebOptionKey::OidcRedirectUrl => ("oidc_redirect_url", "oidc_redirect_url", false),
                };

                server_core::set_server_option(stored_key, &value).await?;
                if is_secret {
                    println!("set {}=<redacted>", label);
                } else {
                    println!("set {}={}", label, value);
                }
            }
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
        AuthPrompt { .. } => {
            // Auth prompts are only used in server mode with interactive auth
            // Not applicable in local TUI mode
            Ok(false)
        }
        BackendEvent(_) => {
            // Backend events are internal signals
            Ok(false)
        }
    }
}

async fn build_app_for_local(name: &str, tab: Option<usize>) -> anyhow::Result<Box<dyn tui_core::TuiApp>> {
    let app = server_core::create_app_by_name(None, name, tab).await?;
    Ok(app)
}
