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
    let role_id = create_role(&pool, "test_role", Some("Test Role")).await.unwrap();
    let roles = list_roles(&pool).await.unwrap();
    assert!(roles.iter().any(|r| r.name == "test_role"));

    // Add claim to role
    add_claim_to_role_by_id(&pool, role_id, &ClaimType::Custom("test:claim".to_string()))
        .await
        .unwrap();

    // Create user
    sqlx::query("INSERT INTO users (username, password_hash) VALUES (?, ?)")
        .bind("test_user")
        .bind("password")
        .execute(&pool)
        .await
        .unwrap();
    let user_id = fetch_user_id_by_name(&pool, "test_user").await.unwrap().unwrap();

    // Assign role to user
    assign_role_to_user_by_ids(&pool, user_id, role_id).await.unwrap();

    // Verify claims
    let mut conn = pool.acquire().await.unwrap();
    let claims = get_user_claims_by_id(&mut conn, user_id).await.unwrap();
    assert!(claims.contains(&ClaimType::Custom("test:claim".to_string())));

    // Revoke role
    let mut conn = pool.acquire().await.unwrap();
    revoke_role_from_user_by_ids(&mut conn, user_id, role_id).await.unwrap();
    let claims_after = get_user_claims_by_id(&mut conn, user_id).await.unwrap();
    assert!(!claims_after.contains(&ClaimType::Custom("test:claim".to_string())));

    // Delete role
    delete_role_by_id(&pool, role_id).await.unwrap();
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
    let user_id = fetch_user_id_by_name(&pool, "admin_user").await.unwrap().unwrap();
    let role_id = fetch_role_id_by_name(&pool, "Super Admin").await.unwrap().unwrap();

    assign_role_to_user_by_ids(&pool, user_id, role_id).await.unwrap();

    let mut conn = pool.acquire().await.unwrap();
    let claims = get_user_claims_by_id(&mut conn, user_id).await.unwrap();
    assert!(claims.contains(&ClaimType::Users(ClaimLevel::Wildcard)));
    assert!(claims.contains(&ClaimType::Roles(ClaimLevel::Wildcard)));
    assert!(claims.contains(&ClaimType::Groups(ClaimLevel::Wildcard)));
    assert!(claims.contains(&ClaimType::Relays(ClaimLevel::Wildcard)));
}

#[tokio::test]
async fn test_super_admin_protection() {
    let db = setup_db().await;
    let pool = db.into_pool();

    // 1. Cannot delete Super Admin role (ID 1)
    let err = delete_role_by_id(&pool, 1).await.unwrap_err();
    assert!(matches!(err, DbError::InvalidOperation { .. }));

    // 2. Cannot revoke Super Admin role from last user
    // Create admin user
    sqlx::query("INSERT INTO users (username, password_hash) VALUES (?, ?)")
        .bind("admin1")
        .bind("pw")
        .execute(&pool)
        .await
        .unwrap();
    let user_id = fetch_user_id_by_name(&pool, "admin1").await.unwrap().unwrap();

    // Assign Super Admin role
    assign_role_to_user_by_ids(&pool, user_id, 1).await.unwrap();

    // Verify we can't revoke (assuming count is 1)
    let mut conn = pool.acquire().await.unwrap();
    let err = revoke_role_from_user_by_ids(&mut conn, user_id, 1).await.unwrap_err();
    assert!(matches!(err, DbError::InvalidOperation { .. }));

    // 3. Cannot modify Super Admin claims
    let err = remove_claim_from_role_by_id(&pool, 1, &ClaimType::Users(ClaimLevel::Wildcard))
        .await
        .unwrap_err();
    assert!(matches!(err, DbError::InvalidOperation { .. }));
}
