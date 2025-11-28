use anyhow::Result;
use serial_test::serial;
use sqlx::SqlitePool;

#[tokio::test]
#[serial]
async fn credential_crud_and_assignment_guard() -> Result<()> {
    unsafe {
        std::env::set_var("RB_SERVER_DB_URL", "sqlite:file:cred_test?mode=memory&cache=shared");
    }

    // Create pool via state-store, run migrations
    let handle = state_store::server_db().await?;
    state_store::migrate_server(&handle).await?;
    let pool: SqlitePool = handle.into_pool();

    // Insert a relay host directly (avoid network hostkey fetch in add_relay_host)
    let host_id = state_store::insert_relay_host(&pool, "h1", "127.0.0.1", 22).await?;

    // Provide secrets passphrase for encryption
    unsafe {
        std::env::set_var("RB_SERVER_SECRETS_PASSPHRASE", "test-passphrase");
    }

    // Create password credential
    let cred_id = server_core::create_password_credential("cred1", Some("user1"), "pw1", "fixed", true).await?;

    // Assign to host
    server_core::assign_credential_by_ids(host_id, cred_id).await?;

    // Deleting while assigned should error
    let err = server_core::delete_credential_by_id(cred_id).await.unwrap_err();
    assert!(err.to_string().contains("in use"));

    // Unassign and delete should succeed
    server_core::unassign_credential_by_id(host_id).await?;
    server_core::delete_credential_by_id(cred_id).await?;

    Ok(())
}
