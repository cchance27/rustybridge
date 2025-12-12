use anyhow::Result;
use server_core::ServerContext;
use sqlx::{Row, SqlitePool};

#[tokio::test]
async fn assign_writes_encrypted_values_and_unassign_removes() -> Result<()> {
    let factory = state_store::test_support::SqliteTestDbFactory::new();
    let (server_db, audit_db) = factory.server_and_audit().await?;
    let master_key = [0x42u8; 32];
    let server = ServerContext::new(server_db, audit_db, master_key);
    let pool: SqlitePool = server.server_db.clone().into_pool();

    let ctx = rb_types::audit::AuditContext::server_cli(None, "test-host");

    let host_id = state_store::insert_relay_host(&pool, "h4", "127.0.0.1", 22).await?;
    let cred_id = server_core::create_password_credential(&server, &ctx, "credA", Some("uA"), "pwA", "fixed", true).await?;

    server_core::assign_credential_by_ids(&server, &ctx, host_id, cred_id).await?;

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

    server_core::unassign_credential_by_id(&server, &ctx, host_id).await?;

    let count: i64 = sqlx::query(
        "SELECT COUNT(*) as c FROM relay_host_options WHERE relay_host_id=? AND key in ('auth.source','auth.id','auth.method')",
    )
    .bind(host_id)
    .fetch_one(&pool)
    .await?
    .get("c");
    assert_eq!(count, 0);
    Ok(())
}
