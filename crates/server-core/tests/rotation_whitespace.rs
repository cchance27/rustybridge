use anyhow::Result;
use secrecy::ExposeSecret;
use serial_test::serial;
use sqlx::Row;

#[tokio::test]
#[serial]
async fn rotation_handles_whitespace_in_inputs() -> Result<()> {
    // Use in-memory DB and set passphrase with trailing whitespace
    unsafe {
        std::env::set_var("RB_SERVER_DB_URL", "sqlite:file:rotation_whitespace_test?mode=memory&cache=shared");
    }
    unsafe {
        std::env::set_var("RB_SERVER_SECRETS_PASSPHRASE", "test-secret  \n"); // Trailing whitespace
    }
    let handle = state_store::server_db().await?;
    state_store::migrate_server(&handle).await?;
    let pool = handle.into_pool();

    // Create a credential
    sqlx::query("INSERT INTO relay_hosts (name, ip, port) VALUES ('h1', '127.0.0.1', 22)")
        .execute(&pool)
        .await?;
    let _cred = server_core::create_password_credential("cred1", Some("user"), "password123", "fixed", true).await?;

    // Rotate with whitespace in both old and new inputs (should be trimmed)
    server_core::rotate_secrets_key("  test-secret\n", "\tnew-secret  ").await?;

    // Verify we can decrypt with trimmed new passphrase
    let new_master = server_core::secrets::derive_master_key_from_passphrase("new-secret").unwrap();
    let row = sqlx::query("SELECT salt, nonce, secret FROM relay_credentials WHERE name='cred1'")
        .fetch_one(&pool)
        .await?;
    let salt: Vec<u8> = row.get("salt");
    let nonce: Vec<u8> = row.get("nonce");
    let secret: Vec<u8> = row.get("secret");

    let dec = server_core::secrets::decrypt_secret_with(&salt, &nonce, &secret, &new_master).unwrap();
    assert_eq!(String::from_utf8(dec.expose_secret().clone()).unwrap(), "password123");

    Ok(())
}
