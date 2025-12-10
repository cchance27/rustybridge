use anyhow::Result;
use serial_test::serial;
use sqlx::{Row, SqlitePool};

mod common;

#[tokio::test]
#[serial]
async fn agent_credential_store() -> Result<()> {
    common::set_test_db_env("agent_test");
    unsafe {
        std::env::set_var("RB_SERVER_SECRETS_PASSPHRASE", "agent-pass");
    }
    let handle = state_store::server_db().await?;
    state_store::migrate_server(&handle).await?;
    let pool: SqlitePool = handle.into_pool();

    // Public key: generate from random private key
    let mut osrng = russh::keys::ssh_key::rand_core::OsRng;
    let privk = russh::keys::PrivateKey::random(&mut osrng, russh::keys::Algorithm::Ed25519)?;
    let pubk = privk.public_key().to_openssh()?.to_string();

    let ctx = rb_types::audit::AuditContext::system("test");
    let _id = server_core::create_agent_credential(&ctx, "credAgent", Some("userA"), &pubk, "fixed").await?;
    let row = sqlx::query("SELECT salt, nonce, secret FROM relay_credentials WHERE name='credAgent'")
        .fetch_one(&pool)
        .await?;
    let ct: Vec<u8> = row.get("secret");
    assert!(!ct.is_empty());
    Ok(())
}
