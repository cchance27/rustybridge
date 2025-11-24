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
    server_core::create_password_credential("credA", Some("uA"), "pwA", "fixed", true).await?;

    server_core::assign_credential("h4", "credA").await?;

    let host_id: i64 = sqlx::query_scalar("SELECT id FROM relay_hosts WHERE name = 'h4'")
        .fetch_one(&pool)
        .await?;
    let cred_id: i64 = sqlx::query_scalar("SELECT id FROM relay_credentials WHERE name = 'credA'")
        .fetch_one(&pool)
        .await?;

    // Verify auth.source, auth.id, and auth.method are stored as PLAIN TEXT (not encrypted)
    let source: String = sqlx::query_scalar("SELECT value FROM relay_host_options WHERE relay_host_id = ? AND key = 'auth.source'")
        .bind(host_id)
        .fetch_one(&pool)
        .await?;
    assert_eq!(source, "credential", "auth.source should be plain text");

    let id_str: String = sqlx::query_scalar("SELECT value FROM relay_host_options WHERE relay_host_id = ? AND key = 'auth.id'")
        .bind(host_id)
        .fetch_one(&pool)
        .await?;
    assert_eq!(id_str, cred_id.to_string(), "auth.id should be plain text");

    let method: String = sqlx::query_scalar("SELECT value FROM relay_host_options WHERE relay_host_id = ? AND key = 'auth.method'")
        .bind(host_id)
        .fetch_one(&pool)
        .await?;
    assert_eq!(method, "password", "auth.method should be plain text");

    // Verify is_secure flag is set to false for these options
    let source_secure: bool =
        sqlx::query_scalar("SELECT is_secure FROM relay_host_options WHERE relay_host_id = ? AND key = 'auth.source'")
            .bind(host_id)
            .fetch_one(&pool)
            .await?;
    assert!(!source_secure, "auth.source should have is_secure=false");

    let id_secure: bool = sqlx::query_scalar("SELECT is_secure FROM relay_host_options WHERE relay_host_id = ? AND key = 'auth.id'")
        .bind(host_id)
        .fetch_one(&pool)
        .await?;
    assert!(!id_secure, "auth.id should have is_secure=false");

    let method_secure: bool =
        sqlx::query_scalar("SELECT is_secure FROM relay_host_options WHERE relay_host_id = ? AND key = 'auth.method'")
            .bind(host_id)
            .fetch_one(&pool)
            .await?;
    assert!(!method_secure, "auth.method should have is_secure=false");

    server_core::unassign_credential("h4").await?;

    let count: i64 = sqlx::query("SELECT COUNT(*) as c FROM relay_host_options WHERE relay_host_id=(SELECT id FROM relay_hosts WHERE name='h4') AND key in ('auth.source','auth.id','auth.method')")
        .fetch_one(&pool)
        .await?
        .get("c");
    assert_eq!(count, 0);
    Ok(())
}
