use anyhow::Result;
use server_core::ServerContext;
use sqlx::{Row, SqlitePool};

#[tokio::test]
async fn agent_credential_store() -> Result<()> {
    let factory = state_store::test_support::SqliteTestDbFactory::new();
    let (server_db, audit_db) = factory.server_and_audit().await?;
    let master_key = [0x42u8; 32];
    let server = ServerContext::new(server_db, audit_db, master_key);
    let pool: SqlitePool = server.server_db.clone().into_pool();

    // Public key: generate from random private key
    let mut osrng = russh::keys::ssh_key::rand_core::OsRng;
    let privk = russh::keys::PrivateKey::random(&mut osrng, russh::keys::Algorithm::Ed25519)?;
    let pubk = privk.public_key().to_openssh()?.to_string();

    let ctx = rb_types::audit::AuditContext::system("test");
    let _id = server_core::create_agent_credential(&server, &ctx, "credAgent", Some("userA"), &pubk, "fixed").await?;
    let row = sqlx::query("SELECT salt, nonce, secret FROM relay_credentials WHERE name='credAgent'")
        .fetch_one(&pool)
        .await?;
    let ct: Vec<u8> = row.get("secret");
    assert!(!ct.is_empty());
    Ok(())
}
