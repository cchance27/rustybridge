use anyhow::Result;
use base64::Engine;
use secrecy::ExposeSecret;
use server_core::ServerContext;
use sqlx::{Row, SqlitePool};

#[tokio::test]
async fn rotation_reencrypts_credentials_and_options() -> Result<()> {
    let factory = state_store::test_support::SqliteTestDbFactory::new();
    let (server_db, audit_db) = factory.server_and_audit().await?;
    let old_key = [0x11u8; 32];
    let new_key = [0x22u8; 32];
    let server = ServerContext::new(server_db, audit_db, old_key);
    let pool: SqlitePool = server.server_db.clone().into_pool();

    let ctx = rb_types::audit::AuditContext::server_cli(None, "test-host");

    // Setup: host + option + credential
    let host_id = state_store::insert_relay_host(&pool, "h3", "127.0.0.1", 22).await?;
    server_core::set_relay_option_by_id(&server, &ctx, host_id, "api.secret", "abc123", true).await?;
    let cred_id = server_core::create_password_credential(&server, &ctx, "credR", Some("ux"), "pw-xyz", "fixed", true).await?;
    server_core::assign_credential_by_ids(&server, &ctx, host_id, cred_id).await?;

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

    // Rotate using old/new base64 master keys (avoids KDF + salt file in tests)
    let old_b64 = base64::engine::general_purpose::STANDARD.encode(old_key);
    let new_b64 = base64::engine::general_purpose::STANDARD.encode(new_key);
    server_core::rotate_secrets_key(&server, &old_b64, &new_b64).await?;

    // Verify ciphertexts changed and plain decrypted matches
    let after_opt: String = sqlx::query("SELECT value FROM relay_host_options WHERE relay_host_id=? AND key='api.secret'")
        .bind(host_id)
        .fetch_one(&pool)
        .await?
        .get("value");
    assert_ne!(before_opt, after_opt);
    let pt_opt = server_core::secrets::decrypt_string_with(&after_opt, &new_key);
    assert_eq!(&**pt_opt.unwrap().expose_secret(), "abc123");

    let after_cred: (Vec<u8>, Vec<u8>, Vec<u8>) = {
        let row = sqlx::query("SELECT salt, nonce, secret FROM relay_credentials WHERE name='credR'")
            .fetch_one(&pool)
            .await?;
        (row.get("salt"), row.get("nonce"), row.get("secret"))
    };
    assert_ne!(before_cred.2, after_cred.2);
    let dec = server_core::secrets::decrypt_secret_with(&after_cred.0, &after_cred.1, &after_cred.2, &new_key).unwrap();
    assert_eq!(String::from_utf8(dec.expose_secret().clone()).unwrap(), "pw-xyz");

    Ok(())
}
