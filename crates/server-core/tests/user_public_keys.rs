use anyhow::Result;
use serial_test::serial;
use sqlx::Row;

#[tokio::test]
#[serial]
async fn add_user_public_key_stores_key() -> Result<()> {
    unsafe {
        std::env::set_var("RB_SERVER_DB_URL", "sqlite:file:user_pubkey_test?mode=memory&cache=shared");
    }
    // Secrets aren't used directly here but set for consistency with other tests.
    unsafe {
        std::env::set_var("RB_SERVER_SECRETS_PASSPHRASE", "pubkey-passphrase");
    }

    let handle = state_store::server_db().await?;
    state_store::migrate_server(&handle).await?;
    let pool = handle.into_pool();

    server_core::add_user("alice", "password").await?;

    // Generate a valid OpenSSH public key
    let mut rng = russh::keys::ssh_key::rand_core::OsRng;
    let privk = russh::keys::PrivateKey::random(&mut rng, russh::keys::Algorithm::Ed25519)?;
    let pubk = privk.public_key().to_openssh()?.to_string();

    let key_id = server_core::add_user_public_key("alice", &pubk, Some("laptop")).await?;

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
#[serial]
async fn list_and_remove_user_public_key() -> Result<()> {
    unsafe {
        std::env::set_var("RB_SERVER_DB_URL", "sqlite:file:user_pubkey_test2?mode=memory&cache=shared");
    }
    unsafe {
        std::env::set_var("RB_SERVER_SECRETS_PASSPHRASE", "pubkey-passphrase");
    }

    let handle = state_store::server_db().await?;
    state_store::migrate_server(&handle).await?;
    let pool = handle.into_pool();

    server_core::add_user("bob", "password").await?;

    let mut rng = russh::keys::ssh_key::rand_core::OsRng;
    let privk = russh::keys::PrivateKey::random(&mut rng, russh::keys::Algorithm::Ed25519)?;
    let pubk = privk.public_key().to_openssh()?.to_string();

    let key_id = server_core::add_user_public_key("bob", &pubk, None).await?;

    let keys = server_core::list_user_public_keys("bob").await?;
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].0, key_id);

    server_core::delete_user_public_key("bob", key_id).await?;

    let keys_after = server_core::list_user_public_keys("bob").await?;
    assert!(keys_after.is_empty());

    // Ensure the DB row is gone
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM user_public_keys WHERE id = ?")
        .bind(key_id)
        .fetch_one(&pool)
        .await?;
    assert_eq!(count, 0);

    Ok(())
}
