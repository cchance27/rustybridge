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

    let ctx = rb_types::audit::AuditContext::server_cli(None, "test-host");

    // Setup: host + option + credential
    let host_id = state_store::insert_relay_host(&pool, "h3", "127.0.0.1", 22).await?;
    server_core::set_relay_option_by_id(&ctx, host_id, "api.secret", "abc123", true).await?;
    let cred_id = server_core::create_password_credential(&ctx, "credR", Some("ux"), "pw-xyz", "fixed", true).await?;
    server_core::assign_credential_by_ids(&ctx, host_id, cred_id).await?;

    // Capture pre-rotation ciphertexts
    let before_opt: String = sqlx::query("SELECT value FROM relay_host_options WHERE relay_host_id=? AND key='api.secret'")
        .bind(host_id)
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
    let after_opt: String = sqlx::query("SELECT value FROM relay_host_options WHERE relay_host_id=? AND key='api.secret'")
        .bind(host_id)
        .fetch_one(&pool)
        .await?
        .get("value");
    assert_ne!(before_opt, after_opt);
    // Derive the new master key from passphrase (matches rotation logic)
    let new_master = server_core::secrets::derive_master_key_from_passphrase("new-secret").unwrap();
    let pt_opt = server_core::secrets::decrypt_string_with(&after_opt, &new_master);
    assert_eq!(&**pt_opt.unwrap().expose_secret(), "abc123");

    let after_cred: (Vec<u8>, Vec<u8>, Vec<u8>) = {
        let row = sqlx::query("SELECT salt, nonce, secret FROM relay_credentials WHERE name='credR'")
            .fetch_one(&pool)
            .await?;
        (row.get("salt"), row.get("nonce"), row.get("secret"))
    };
    assert_ne!(before_cred.2, after_cred.2);
    let dec = server_core::secrets::decrypt_secret_with(&after_cred.0, &after_cred.1, &after_cred.2, &new_master).unwrap();
    assert_eq!(String::from_utf8(dec.expose_secret().clone()).unwrap(), "pw-xyz");

    Ok(())
}
