use chrono::Utc;
use rb_types::state::DbHandle;
use uuid::Uuid;

#[derive(Debug, Clone, Copy)]
pub enum ConnectionType {
    Web,
    Ssh,
}

impl ConnectionType {
    fn as_str(&self) -> &'static str {
        match self {
            ConnectionType::Web => "web",
            ConnectionType::Ssh => "ssh",
        }
    }
}

/// Record a new SSH connection for audit trail
pub async fn record_ssh_connection(
    db: &DbHandle,
    user_id: i64,
    ip_address: String,
    ssh_client: Option<String>,
    connection_id: Option<String>,
) -> Result<String, sqlx::Error> {
    let connection_id = connection_id.unwrap_or_else(|| Uuid::now_v7().to_string());
    let connected_at = Utc::now().timestamp_millis();

    sqlx::query(
        "INSERT INTO client_sessions 
         (id, user_id, connection_type, ip_address, connected_at, ssh_client) 
         VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(&connection_id)
    .bind(user_id)
    .bind(ConnectionType::Ssh.as_str())
    .bind(&ip_address)
    .bind(connected_at)
    .bind(ssh_client)
    .execute(&db.pool)
    .await?;

    Ok(connection_id)
}

/// Record a new web connection for audit trail
pub async fn record_web_connection(
    db: &DbHandle,
    connection_id: String, // WebSocket session UUID from browser
    user_id: i64,
    ip_address: Option<String>,
    user_agent: Option<String>,
    parent_session_id: Option<String>,
) -> Result<(), sqlx::Error> {
    let connected_at = Utc::now().timestamp_millis();

    sqlx::query(
        "INSERT OR IGNORE INTO client_sessions 
         (id, user_id, connection_type, ip_address, user_agent, connected_at, parent_session_id) 
         VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&connection_id)
    .bind(user_id)
    .bind(ConnectionType::Web.as_str())
    .bind(ip_address.unwrap_or_else(|| "unknown".to_string()))
    .bind(user_agent)
    .bind(connected_at)
    .bind(parent_session_id)
    .execute(&db.pool)
    .await?;

    Ok(())
}

/// Mark a connection as disconnected
pub async fn record_disconnection(db: &DbHandle, connection_id: &str) -> Result<(), sqlx::Error> {
    let disconnected_at = Utc::now().timestamp_millis();

    sqlx::query("UPDATE client_sessions SET disconnected_at = ? WHERE id = ?")
        .bind(disconnected_at)
        .bind(connection_id)
        .execute(&db.pool)
        .await?;

    Ok(())
}
