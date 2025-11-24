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
    sqlx::query("INSERT INTO relay_hosts (name, ip, port) VALUES ('h1', '127.0.0.1', 22)")
        .execute(&pool)
        .await?;

    // Provide secrets passphrase for encryption
    unsafe {
        std::env::set_var("RB_SERVER_SECRETS_PASSPHRASE", "test-passphrase");
    }

    // Create password credential
    let _id = server_core::create_password_credential("cred1", Some("user1"), "pw1", "fixed", true).await?;

    // Assign to host
    server_core::assign_credential("h1", "cred1").await?;

    // Deleting while assigned should error
    let err = server_core::delete_credential("cred1").await.unwrap_err();
    assert!(err.to_string().contains("assigned"));

    // Unassign and delete should succeed
    server_core::unassign_credential("h1").await?;
    server_core::delete_credential("cred1").await?;

    Ok(())
}
