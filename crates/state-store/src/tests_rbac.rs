use sqlx::SqlitePool;

use crate::*;

async fn setup_db() -> DbHandle {
    // Use in-memory DB for testing
    let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
    let handle = DbHandle {
        pool,
        url: "sqlite::memory:".to_string(),
        path: None,
        freshly_created: true,
    };
    migrate_server(&handle).await.unwrap();
    handle
}

#[tokio::test]
async fn test_role_management() {
    let db = setup_db().await;
    let pool = db.into_pool();

    // Create role
    create_role(&pool, "test_role", Some("Test Role")).await.unwrap();
    let roles = list_roles(&pool).await.unwrap();
    assert!(roles.iter().any(|r| r.name == "test_role"));

    // Add claim to role
    add_claim_to_role(&pool, "test_role", &ClaimType::Custom("test:claim".to_string()))
        .await
        .unwrap();

    // Create user
    sqlx::query("INSERT INTO users (username, password_hash) VALUES (?, ?)")
        .bind("test_user")
        .bind("password")
        .execute(&pool)
        .await
        .unwrap();

    // Assign role to user
    assign_role_to_user(&pool, "test_user", "test_role").await.unwrap();

    // Verify claims
    let claims = get_user_claims(&pool, "test_user").await.unwrap();
    assert!(claims.contains(&ClaimType::Custom("test:claim".to_string())));

    // Revoke role
    revoke_role_from_user(&pool, "test_user", "test_role").await.unwrap();
    let claims_after = get_user_claims(&pool, "test_user").await.unwrap();
    assert!(!claims_after.contains(&ClaimType::Custom("test:claim".to_string())));

    // Delete role
    delete_role(&pool, "test_role").await.unwrap();
    let roles_after = list_roles(&pool).await.unwrap();
    assert!(!roles_after.iter().any(|r| r.name == "test_role"));
}

#[tokio::test]
async fn test_default_admin_role() {
    let db = setup_db().await;
    let pool = db.into_pool();

    // The migration should have created 'Super Admin' and 'User' roles
    let roles = list_roles(&pool).await.unwrap();
    assert!(roles.iter().any(|r| r.name == "Super Admin"));
    assert!(roles.iter().any(|r| r.name == "User"));

    // Check Super Admin claims
    // We can't easily check role claims directly without a function, but we can check via a user
    sqlx::query("INSERT INTO users (username, password_hash) VALUES (?, ?)")
        .bind("admin_user")
        .bind("password")
        .execute(&pool)
        .await
        .unwrap();
    assign_role_to_user(&pool, "admin_user", "Super Admin").await.unwrap();

    let claims = get_user_claims(&pool, "admin_user").await.unwrap();
    assert!(claims.contains(&ClaimType::Custom("*".to_string())));
}
