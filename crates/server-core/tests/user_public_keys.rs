use anyhow::Result;
use server_core::ServerContext;
use sqlx::Row;

#[tokio::test]
async fn add_user_public_key_stores_key() -> Result<()> {
    let factory = state_store::test_support::SqliteTestDbFactory::new();
    let (server_db, audit_db) = factory.server_and_audit().await?;
    let master_key = [0x42u8; 32];
    let server = ServerContext::new(server_db, audit_db, master_key);
    let pool = server.server_db.clone().into_pool();

    let ctx = rb_types::audit::AuditContext::system("test");
    server_core::add_user(&server, &ctx, "alice", "password").await?;

    // Generate a valid OpenSSH public key
    let mut rng = russh::keys::ssh_key::rand_core::OsRng;
    let privk = russh::keys::PrivateKey::random(&mut rng, russh::keys::Algorithm::Ed25519)?;
    let pubk = privk.public_key().to_openssh()?.to_string();

    let key_id = server_core::add_user_public_key(&server, &ctx, "alice", &pubk, Some("laptop")).await?;

    let row = sqlx::query("SELECT public_key, comment FROM user_public_keys WHERE id = ?")
        .bind(key_id)
        .fetch_one(&pool)
        .await?;
    let stored_key: String = row.get("public_key");
    let stored_comment: Option<String> = row.get("comment");

    assert_eq!(stored_key.trim(), pubk.trim());
    assert_eq!(stored_comment.as_deref(), Some("laptop"));

    let keys = state_store::get_user_public_keys(&pool, "alice").await?;
    assert!(keys.iter().any(|k| k.trim() == pubk.trim()));

    Ok(())
}

#[tokio::test]
async fn list_and_remove_user_public_key() -> Result<()> {
    let factory = state_store::test_support::SqliteTestDbFactory::new();
    let (server_db, audit_db) = factory.server_and_audit().await?;
    let master_key = [0x42u8; 32];
    let server = ServerContext::new(server_db, audit_db, master_key);
    let pool = server.server_db.clone().into_pool();

    let ctx = rb_types::audit::AuditContext::system("test");
    server_core::add_user(&server, &ctx, "bob", "password").await?;

    let mut rng = russh::keys::ssh_key::rand_core::OsRng;
    let privk = russh::keys::PrivateKey::random(&mut rng, russh::keys::Algorithm::Ed25519)?;
    let pubk = privk.public_key().to_openssh()?.to_string();

    let key_id = server_core::add_user_public_key(&server, &ctx, "bob", &pubk, None).await?;

    let keys = server_core::list_user_public_keys(&server, "bob").await?;
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].0, key_id);

    server_core::delete_user_public_key(&server, &ctx, "bob", key_id).await?;

    let keys_after = server_core::list_user_public_keys(&server, "bob").await?;
    assert!(keys_after.is_empty());

    // Ensure the DB row is gone
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM user_public_keys WHERE id = ?")
        .bind(key_id)
        .fetch_one(&pool)
        .await?;
    assert_eq!(count, 0);

    Ok(())
}
