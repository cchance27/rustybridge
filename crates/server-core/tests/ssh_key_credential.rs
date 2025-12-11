use anyhow::Result;
use serial_test::serial;
use sqlx::{Row, SqlitePool};

mod common;

#[tokio::test]
#[serial]
async fn ssh_key_credential_store_and_assign() -> Result<()> {
    common::set_test_db_env("sshkey_test");
    unsafe {
        std::env::set_var("RB_SERVER_SECRETS_PASSPHRASE", "sshkey-pass");
    }
    let handle = state_store::server_db().await?;
    state_store::migrate_server(&handle).await?;
    let pool: SqlitePool = handle.into_pool();

    let host_id = state_store::insert_relay_host(&pool, "h5", "127.0.0.1", 22).await?;

    // Generate a throwaway private key in OpenSSH format
    let mut osrng = russh::keys::ssh_key::rand_core::OsRng;
    let key = russh::keys::PrivateKey::random(&mut osrng, russh::keys::Algorithm::Ed25519)?;
    let key_pem = key.to_openssh(russh::keys::ssh_key::LineEnding::LF)?.to_string();

    let ctx = rb_types::audit::AuditContext::system("test");
    let cred_id = server_core::create_ssh_key_credential(&ctx, "credK", Some("userK"), &key_pem, None, None, "fixed").await?;
    // Ensure stored secret is there
    let row = sqlx::query("SELECT salt, nonce, secret FROM relay_credentials WHERE name='credK'")
        .fetch_one(&pool)
        .await?;
    let ct: Vec<u8> = row.get("secret");
    assert!(!ct.is_empty());

    server_core::assign_credential_by_ids(&ctx, host_id, cred_id).await?;
    // Ensure method is stored as plain text "publickey" (not encrypted)
    let method: String = sqlx::query("SELECT value FROM relay_host_options WHERE relay_host_id=? AND key='auth.method'")
        .bind(host_id)
        .fetch_one(&pool)
        .await?
        .get("value");
    assert_eq!(method, "publickey", "auth.method should be plain text 'publickey'");

    Ok(())
}
