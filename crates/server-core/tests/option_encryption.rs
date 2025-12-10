use anyhow::Result;
use serial_test::serial;
use sqlx::{Row, SqlitePool};

mod common;

#[tokio::test]
#[serial]
async fn option_encryption_and_masked_listing() -> Result<()> {
    common::set_test_db_env("option_test");
    unsafe {
        std::env::set_var("RB_SERVER_SECRETS_PASSPHRASE", "pass-old");
    }
    let handle = state_store::server_db().await?;
    state_store::migrate_server(&handle).await?;
    let pool: SqlitePool = handle.into_pool();

    // Insert host
    let host_id = state_store::insert_relay_host(&pool, "h2", "127.0.0.1", 22).await?;

    let ctx = rb_types::audit::AuditContext::server_cli(None, "test-host");

    // Set an option
    server_core::set_relay_option_by_id(&ctx, host_id, "api.secret", "supersecret", true).await?;

    // Verify it's encrypted at rest
    let row = sqlx::query("SELECT value FROM relay_host_options WHERE relay_host_id = ? AND key='api.secret'")
        .bind(host_id)
        .fetch_one(&pool)
        .await?;
    let stored: String = row.get("value");
    assert!(server_core::secrets::is_encrypted_marker(&stored));

    // List via helper: should be masked
    let items = server_core::list_options_by_id(host_id).await?;
    let (_, v) = items.into_iter().find(|(k, _)| k == "api.secret").expect("entry");
    assert_eq!(v, "<encrypted>");
    Ok(())
}
