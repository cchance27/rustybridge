#[cfg(feature = "server")]
use base64::Engine;

#[cfg(feature = "server")]
use anyhow::Result;
#[cfg(feature = "server")]
use secrecy::ExposeSecret;
#[cfg(feature = "server")]
use sqlx::Row;

#[cfg(not(feature = "server"))]
fn main() {}

#[cfg(feature = "server")]
#[tokio::main]
async fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let session_id = args
        .next()
        .expect("usage: dump_chunk <session_id> <chunk_index>");
    let chunk_index: i64 = args
        .next()
        .expect("usage: dump_chunk <session_id> <chunk_index>")
        .parse()
        .expect("chunk_index must be integer");

    let audit_db = state_store::audit::audit_db().await?;
    let row = sqlx::query(
        r#"
        SELECT direction, data, timestamp
        FROM session_chunks
        WHERE session_id = ? AND chunk_index = ?
        "#,
    )
    .bind(&session_id)
    .bind(chunk_index)
    .fetch_one(&audit_db.pool)
    .await?;

    let direction: i32 = row.get("direction");
    let encrypted: Vec<u8> = row.get("data");
    let timestamp: i64 = row.get("timestamp");

    let (salt, rest) = encrypted.split_at(16);
    let (nonce, ciphertext) = rest.split_at(24);

    let (compressed, _) = server_core::secrets::decrypt_secret(salt, nonce, ciphertext)?;
    let plaintext = zstd::decode_all(compressed.expose_secret().as_slice())?;

    println!("chunk_index: {chunk_index}");
    println!("direction: {direction}");
    println!("timestamp: {timestamp}");
    println!("plaintext_len: {}", plaintext.len());

    // show first 300 bytes printable
    let preview = String::from_utf8_lossy(&plaintext);
    let preview = preview.chars().take(600).collect::<String>();
    println!("preview:\n{}", preview);

    // also output base64 for debugging
    let b64 = base64::engine::general_purpose::STANDARD.encode(&plaintext);
    println!("base64_len: {}", b64.len());
    println!("base64_prefix: {}", &b64[..b64.len().min(120)]);

    Ok(())
}
