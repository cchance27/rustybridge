use anyhow::Result;
use server_core::ServerContext;
use sqlx::SqlitePool;

#[tokio::test]
async fn credential_crud_and_assignment_guard() -> Result<()> {
    let factory = state_store::test_support::SqliteTestDbFactory::new();
    let (server_db, audit_db) = factory.server_and_audit().await?;
    let master_key = [0x42u8; 32];
    let server = ServerContext::new(server_db, audit_db, master_key);
    let pool: SqlitePool = server.server_db.clone().into_pool();

    // Insert a relay host directly (avoid network hostkey fetch in add_relay_host)
    let host_id = state_store::insert_relay_host(&pool, "h1", "127.0.0.1", 22).await?;

    let ctx = rb_types::audit::AuditContext::server_cli(None, "test-host");

    // Create password credential
    let cred_id = server_core::create_password_credential(&server, &ctx, "cred1", Some("user1"), "pw1", "fixed", true).await?;

    // Assign to host
    server_core::assign_credential_by_ids(&server, &ctx, host_id, cred_id).await?;

    // Deleting while assigned should error
    let err = server_core::delete_credential_by_id(&server, &ctx, cred_id).await.unwrap_err();
    assert!(err.to_string().contains("in use"));

    // Unassign and delete should succeed
    server_core::unassign_credential_by_id(&server, &ctx, host_id).await?;
    server_core::delete_credential_by_id(&server, &ctx, cred_id).await?;

    Ok(())
}
