use anyhow::Result;
use server_core::ServerContext;
use sqlx::{Row, SqlitePool};

#[tokio::test]
async fn option_encryption_and_masked_listing() -> Result<()> {
    let factory = state_store::test_support::SqliteTestDbFactory::new();
    let (server_db, audit_db) = factory.server_and_audit().await?;
    let master_key = [0x42u8; 32];
    let server = ServerContext::new(server_db, audit_db, master_key);
    let pool: SqlitePool = server.server_db.clone().into_pool();

    // Insert host
    let host_id = state_store::insert_relay_host(&pool, "h2", "127.0.0.1", 22).await?;

    let ctx = rb_types::audit::AuditContext::server_cli(None, "test-host");

    // Set an option
    server_core::set_relay_option_by_id(&server, &ctx, host_id, "api.secret", "supersecret", true).await?;

    // Verify it's encrypted at rest
    let row = sqlx::query("SELECT value FROM relay_host_options WHERE relay_host_id = ? AND key='api.secret'")
        .bind(host_id)
        .fetch_one(&pool)
        .await?;
    let stored: String = row.get("value");
    assert!(server_core::secrets::is_encrypted_marker(&stored));

    // List via helper: should be masked
    let items = server_core::list_options_by_id(&server, host_id).await?;
    let (_, v) = items.into_iter().find(|(k, _)| k == "api.secret").expect("entry");
    assert_eq!(v, "<encrypted>");
    Ok(())
}
