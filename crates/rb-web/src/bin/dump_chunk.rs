#[cfg(feature = "server")]
use anyhow::{Result, anyhow};
#[cfg(feature = "server")]
use base64::Engine;
#[cfg(feature = "server")]
use server_core::api::SessionChunk;

#[cfg(not(feature = "server"))]
fn main() {}

#[cfg(feature = "server")]
#[tokio::main]
async fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let session_id = args.next().expect("usage: dump_chunk <session_id> <chunk_index>");
    let chunk_index: i64 = args
        .next()
        .expect("usage: dump_chunk <session_id> <chunk_index>")
        .parse()
        .expect("chunk_index must be integer");

    let chunks = server_core::api::fetch_session_chunks(&session_id).await?;
    let chunk: SessionChunk = chunks
        .into_iter()
        .find(|c| c.db_chunk_index == Some(chunk_index as usize))
        .ok_or_else(|| anyhow!("chunk {} not found", chunk_index))?;

    let plaintext = base64::engine::general_purpose::STANDARD
        .decode(&chunk.data)
        .map_err(|e| anyhow::anyhow!("base64 decode failed: {e}"))?;

    println!("chunk_index: {chunk_index}");
    println!("direction: {}", chunk.direction);
    println!("timestamp: {}", chunk.timestamp);
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
