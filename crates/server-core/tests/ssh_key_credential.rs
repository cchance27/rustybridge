use anyhow::Result;
use server_core::ServerContext;
use sqlx::{Row, SqlitePool};

#[tokio::test]
async fn ssh_key_credential_store_and_assign() -> Result<()> {
    let factory = state_store::test_support::SqliteTestDbFactory::new();
    let (server_db, audit_db) = factory.server_and_audit().await?;
    let master_key = [0x42u8; 32];
    let server = ServerContext::new(server_db, audit_db, master_key);
    let pool: SqlitePool = server.server_db.clone().into_pool();

    let host_id = state_store::insert_relay_host(&pool, "h5", "127.0.0.1", 22).await?;

    // Generate a throwaway private key in OpenSSH format
    let mut osrng = russh::keys::ssh_key::rand_core::OsRng;
    let key = russh::keys::PrivateKey::random(&mut osrng, russh::keys::Algorithm::Ed25519)?;
    let key_pem = key.to_openssh(russh::keys::ssh_key::LineEnding::LF)?.to_string();

    let ctx = rb_types::audit::AuditContext::system("test");
    let cred_id = server_core::create_ssh_key_credential(&server, &ctx, "credK", Some("userK"), &key_pem, None, None, "fixed").await?;
    // Ensure stored secret is there
    let row = sqlx::query("SELECT salt, nonce, secret FROM relay_credentials WHERE name='credK'")
        .fetch_one(&pool)
        .await?;
    let ct: Vec<u8> = row.get("secret");
    assert!(!ct.is_empty());

    server_core::assign_credential_by_ids(&server, &ctx, host_id, cred_id).await?;
    // Ensure method is stored as plain text "publickey" (not encrypted)
    let method: String = sqlx::query("SELECT value FROM relay_host_options WHERE relay_host_id=? AND key='auth.method'")
        .bind(host_id)
        .fetch_one(&pool)
        .await?
        .get("value");
    assert_eq!(method, "publickey", "auth.method should be plain text 'publickey'");

    Ok(())
}
