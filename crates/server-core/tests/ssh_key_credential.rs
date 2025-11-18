use anyhow::Result;
use serial_test::serial;
use sqlx::{Row, SqlitePool};

#[tokio::test]
#[serial]
async fn ssh_key_credential_store_and_assign() -> Result<()> {
    unsafe {
        std::env::set_var("RB_SERVER_DB_URL", "sqlite:file:sshkey_test?mode=memory&cache=shared");
    }
    unsafe {
        std::env::set_var("RB_SERVER_SECRETS_PASSPHRASE", "sshkey-pass");
    }
    let handle = state_store::server_db().await?;
    state_store::migrate_server(&handle).await?;
    let pool: SqlitePool = handle.into_pool();

    sqlx::query("INSERT INTO relay_hosts (name, ip, port) VALUES ('h5', '127.0.0.1', 22)")
        .execute(&pool)
        .await?;

    // Generate a throwaway private key in OpenSSH format
    let mut osrng = russh::keys::ssh_key::rand_core::OsRng;
    let key = russh::keys::PrivateKey::random(&mut osrng, russh::keys::Algorithm::Ed25519)?;
    let key_pem = key.to_openssh(russh::keys::ssh_key::LineEnding::LF)?.to_string();

    let _id = server_core::create_ssh_key_credential("credK", Some("userK"), &key_pem, None, None).await?;
    // Ensure stored secret is there
    let row = sqlx::query("SELECT salt, nonce, secret FROM relay_credentials WHERE name='credK'")
        .fetch_one(&pool)
        .await?;
    let ct: Vec<u8> = row.get("secret");
    assert!(!ct.is_empty());

    server_core::assign_credential("h5", "credK").await?;
    // Ensure method reflects publickey (encrypted normalization)
    let method: String = sqlx::query(
        "SELECT value FROM relay_host_options WHERE relay_host_id=(SELECT id FROM relay_hosts WHERE name='h5') AND key='auth.method'",
    )
    .fetch_one(&pool)
    .await?
    .get("value");
    assert!(server_core::secrets::is_encrypted_marker(&method));
    let plain = server_core::secrets::decrypt_string_if_encrypted(&method)?;
    assert_eq!(plain, "publickey");

    Ok(())
}
