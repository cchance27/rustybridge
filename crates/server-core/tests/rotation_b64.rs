use anyhow::Result;
use base64::Engine;
use serial_test::serial;
use sqlx::{Row, SqlitePool};

#[tokio::test]
#[serial]
async fn rotation_with_base64_master_keys() -> Result<()> {
    unsafe {
        std::env::set_var("RB_SERVER_DB_URL", "sqlite:file:rotation_b64?mode=memory&cache=shared");
    }
    // Start with old KEY (base64)
    let old_key = [0x11u8; 32];
    let old_b64 = base64::engine::general_purpose::STANDARD.encode(old_key);
    unsafe {
        std::env::set_var("RB_SERVER_SECRETS_KEY", &old_b64);
    }

    let handle = state_store::server_db().await?;
    state_store::migrate_server(&handle).await?;
    let pool: SqlitePool = handle.into_pool();

    sqlx::query("INSERT INTO relay_hosts (name, ip, port) VALUES ('b64h', '127.0.0.1', 22)")
        .execute(&pool)
        .await?;
    server_core::set_relay_option("b64h", "secret", "val").await?;

    let before: String = sqlx::query(
        "SELECT value FROM relay_host_options WHERE relay_host_id=(SELECT id FROM relay_hosts WHERE name='b64h') AND key='secret'",
    )
    .fetch_one(&pool)
    .await?
    .get("value");

    // Rotate to a new base64 key
    let new_key = [0x22u8; 32];
    let new_b64 = base64::engine::general_purpose::STANDARD.encode(new_key);
    server_core::rotate_secrets_key(&old_b64, &new_b64).await?;

    let after: String = sqlx::query(
        "SELECT value FROM relay_host_options WHERE relay_host_id=(SELECT id FROM relay_hosts WHERE name='b64h') AND key='secret'",
    )
    .fetch_one(&pool)
    .await?
    .get("value");
    assert_ne!(before, after);
    let pt = server_core::secrets::decrypt_string_with(&after, &new_key).unwrap();
    assert_eq!(pt, "val");
    Ok(())
}
