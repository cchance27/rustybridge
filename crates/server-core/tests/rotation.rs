use anyhow::Result;
use secrecy::ExposeSecret;
use serial_test::serial;
use sqlx::{Row, SqlitePool};

#[tokio::test]
#[serial]
async fn rotation_reencrypts_credentials_and_options() -> Result<()> {
    // Use in-memory DB and set OLD passphrase
    unsafe {
        std::env::set_var("RB_SERVER_DB_URL", "sqlite:file:rotation_test?mode=memory&cache=shared");
    }
    unsafe {
        std::env::set_var("RB_SERVER_SECRETS_PASSPHRASE", "old-secret");
    }
    let handle = state_store::server_db().await?;
    state_store::migrate_server(&handle).await?;
    let pool: SqlitePool = handle.into_pool();

    // Setup: host + option + credential
    sqlx::query("INSERT INTO relay_hosts (name, ip, port) VALUES ('h3', '127.0.0.1', 22)")
        .execute(&pool)
        .await?;
    server_core::set_relay_option("h3", "api.secret", "abc123").await?;
    let _cred = server_core::create_password_credential("credR", Some("ux"), "pw-xyz").await?;
    server_core::assign_credential("h3", "credR").await?;

    // Capture pre-rotation ciphertexts
    let before_opt: String = sqlx::query(
        "SELECT value FROM relay_host_options WHERE relay_host_id=(SELECT id FROM relay_hosts WHERE name='h3') AND key='api.secret'",
    )
    .fetch_one(&pool)
    .await?
    .get("value");
    let before_cred: (Vec<u8>, Vec<u8>, Vec<u8>) = {
        let row = sqlx::query("SELECT salt, nonce, secret FROM relay_credentials WHERE name='credR'")
            .fetch_one(&pool)
            .await?;
        (row.get("salt"), row.get("nonce"), row.get("secret"))
    };

    // Rotate using old/new passphrases
    server_core::rotate_secrets_key("old-secret", "new-secret").await?;

    // Verify ciphertexts changed and plain decrypted matches
    let after_opt: String = sqlx::query(
        "SELECT value FROM relay_host_options WHERE relay_host_id=(SELECT id FROM relay_hosts WHERE name='h3') AND key='api.secret'",
    )
    .fetch_one(&pool)
    .await?
    .get("value");
    assert_ne!(before_opt, after_opt);
    let pt_opt = server_core::secrets::decrypt_string_with(&after_opt, b"new-secret");
    assert_eq!(&**pt_opt.unwrap().expose_secret(), "abc123");

    let after_cred: (Vec<u8>, Vec<u8>, Vec<u8>) = {
        let row = sqlx::query("SELECT salt, nonce, secret FROM relay_credentials WHERE name='credR'")
            .fetch_one(&pool)
            .await?;
        (row.get("salt"), row.get("nonce"), row.get("secret"))
    };
    assert_ne!(before_cred.2, after_cred.2);
    let dec = server_core::secrets::decrypt_secret_with(&after_cred.0, &after_cred.1, &after_cred.2, b"new-secret").unwrap();
    assert_eq!(String::from_utf8(dec.expose_secret().clone()).unwrap(), "pw-xyz");

    Ok(())
}
