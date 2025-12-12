use anyhow::Result;
use base64::Engine;
use secrecy::ExposeSecret;
use server_core::ServerContext;
use sqlx::Row;

#[tokio::test]
async fn rotation_handles_whitespace_in_inputs() -> Result<()> {
    let factory = state_store::test_support::SqliteTestDbFactory::new();
    let (server_db, audit_db) = factory.server_and_audit().await?;
    let old_key = [0x11u8; 32];
    let new_key = [0x22u8; 32];
    let old_b64 = base64::engine::general_purpose::STANDARD.encode(old_key);
    let new_b64 = base64::engine::general_purpose::STANDARD.encode(new_key);
    let server = ServerContext::new(server_db, audit_db, old_key);
    let pool = server.server_db.clone().into_pool();

    let ctx = rb_types::audit::AuditContext::server_cli(None, "test-host");

    // Create a credential
    let _host_id = state_store::insert_relay_host(&pool, "h1", "127.0.0.1", 22).await?;
    let _cred = server_core::create_password_credential(&server, &ctx, "cred1", Some("user"), "password123", "fixed", true).await?;

    // Rotate with whitespace in both old and new inputs (should be trimmed)
    server_core::rotate_secrets_key(&server, &format!("  {old_b64}\n"), &format!("\t{new_b64}  ")).await?;

    // Verify we can decrypt with the new key
    let row = sqlx::query("SELECT salt, nonce, secret FROM relay_credentials WHERE name='cred1'")
        .fetch_one(&pool)
        .await?;
    let salt: Vec<u8> = row.get("salt");
    let nonce: Vec<u8> = row.get("nonce");
    let secret: Vec<u8> = row.get("secret");

    let dec = server_core::secrets::decrypt_secret_with(&salt, &nonce, &secret, &new_key).unwrap();
    assert_eq!(String::from_utf8(dec.expose_secret().clone()).unwrap(), "password123");

    Ok(())
}
