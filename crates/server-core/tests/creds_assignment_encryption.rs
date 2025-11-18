use anyhow::Result;
use serial_test::serial;
use sqlx::{Row, SqlitePool};

#[tokio::test]
#[serial]
async fn assign_writes_encrypted_values_and_unassign_removes() -> Result<()> {
    unsafe {
        std::env::set_var("RB_SERVER_DB_URL", "sqlite:file:assign_test?mode=memory&cache=shared");
    }
    unsafe {
        std::env::set_var("RB_SERVER_SECRETS_PASSPHRASE", "assign-pass");
    }

    let handle = state_store::server_db().await?;
    state_store::migrate_server(&handle).await?;
    let pool: SqlitePool = handle.into_pool();

    sqlx::query("INSERT INTO relay_hosts (name, ip, port) VALUES ('h4', '127.0.0.1', 22)")
        .execute(&pool)
        .await?;
    server_core::create_password_credential("credA", Some("uA"), "pwA").await?;

    server_core::assign_credential("h4", "credA").await?;

    // Keys should exist and be encrypted
    for key in ["auth.source", "auth.id", "auth.method"] {
        let row =
            sqlx::query("SELECT value FROM relay_host_options WHERE relay_host_id=(SELECT id FROM relay_hosts WHERE name='h4') AND key=?")
                .bind(key)
                .fetch_one(&pool)
                .await?;
        let val: String = row.get("value");
        assert!(server_core::secrets::is_encrypted_marker(&val), "{} should be encrypted", key);
    }

    server_core::unassign_credential("h4").await?;

    let count: i64 = sqlx::query("SELECT COUNT(*) as c FROM relay_host_options WHERE relay_host_id=(SELECT id FROM relay_hosts WHERE name='h4') AND key in ('auth.source','auth.id','auth.method')")
        .fetch_one(&pool)
        .await?
        .get("c");
    assert_eq!(count, 0);
    Ok(())
}
