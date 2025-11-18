use anyhow::Result;
use rb_cli::{
    init_tracing, server_cli::{ServerArgs, ServerCommand}
};
use server_core::{
    add_relay_host,
    grant_relay_access,
    list_access,
    list_hosts,
    list_options,
    list_users,
    add_user,
    remove_user,
    refresh_target_hostkey,
    revoke_relay_access,
    run_server,
    set_relay_option,
    unset_relay_option,
};

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();
    match ServerArgs::parse_command()? {
        ServerCommand::Run(cfg) => run_server(cfg).await?,
        ServerCommand::AddRelayHost { endpoint, name } => add_relay_host(&endpoint, &name).await?,
        ServerCommand::GrantAccess { name, user } => grant_relay_access(&name, &user).await?,
        ServerCommand::SetOption { name, key, value } => set_relay_option(&name, &key, &value).await?,
        ServerCommand::UnsetOption { name, key } => unset_relay_option(&name, &key).await?,
        ServerCommand::RevokeAccess { name, user } => revoke_relay_access(&name, &user).await?,
        ServerCommand::ListHosts => {
            let items = list_hosts().await?;
            for h in items {
                println!("{} {}:{}", h.name, h.ip, h.port);
            }
        }
        ServerCommand::ListOptions { name } => {
            let items = list_options(&name).await?;
            for (k, v) in items {
                println!("{}={}", k, v);
            }
        }
        ServerCommand::ListAccess { name } => {
            let users = list_access(&name).await?;
            for u in users { println!("{}", u); }
        }
        ServerCommand::AddUser { user, password } => {
            let pass = if let Some(p) = password { p } else { rpassword::prompt_password(format!("Enter password for {user}: "))? };
            add_user(&user, &pass).await?;
        }
        ServerCommand::RemoveUser { user } => {
            remove_user(&user).await?;
        }
        ServerCommand::ListUsers => {
            for u in list_users().await? { println!("{}", u); }
        }
        ServerCommand::RefreshTargetHostkey { name } => {
            refresh_target_hostkey(&name).await?;
        }
    }
    Ok(())
}
