use anyhow::Result;
use base64::Engine;
use secrecy::ExposeSecret;
use server_core::ServerContext;
use sqlx::{Row, SqlitePool};

#[tokio::test]
async fn rotation_with_base64_master_keys() -> Result<()> {
    let factory = state_store::test_support::SqliteTestDbFactory::new();
    let (server_db, audit_db) = factory.server_and_audit().await?;

    // Start with old KEY (base64)
    let old_key = [0x11u8; 32];
    let old_b64 = base64::engine::general_purpose::STANDARD.encode(old_key);
    let server = ServerContext::new(server_db, audit_db, old_key);
    let pool: SqlitePool = server.server_db.clone().into_pool();

    let host_id = state_store::insert_relay_host(&pool, "b64h", "127.0.0.1", 22).await?;
    let ctx = rb_types::audit::AuditContext::server_cli(None, "test-host");
    server_core::set_relay_option_by_id(&server, &ctx, host_id, "secret", "val", true).await?;

    let before: String = sqlx::query("SELECT value FROM relay_host_options WHERE relay_host_id=? AND key='secret'")
        .bind(host_id)
        .fetch_one(&pool)
        .await?
        .get("value");

    // Rotate to a new base64 key
    let new_key = [0x22u8; 32];
    let new_b64 = base64::engine::general_purpose::STANDARD.encode(new_key);
    server_core::rotate_secrets_key(&server, &old_b64, &new_b64).await?;

    let after: String = sqlx::query("SELECT value FROM relay_host_options WHERE relay_host_id=? AND key='secret'")
        .bind(host_id)
        .fetch_one(&pool)
        .await?
        .get("value");
    assert_ne!(before, after);
    let pt = server_core::secrets::decrypt_string_with(&after, &new_key).unwrap();
    assert_eq!(&**pt.expose_secret(), "val");
    Ok(())
}
