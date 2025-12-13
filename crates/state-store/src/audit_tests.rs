//! Tests for audit event logging.
use rb_types::{
    audit::{AuditEvent, ClientType, EventCategory, EventFilter, EventType}, state::DbHandle
};

use crate::audit::events::{count_audit_events, insert_audit_event, query_audit_events};

async fn setup_test_db() -> DbHandle {
    // Create in-memory SQLite database
    let pool = sqlx::SqlitePool::connect("sqlite::memory:")
        .await
        .expect("Failed to create in-memory DB");

    // Run migrations
    sqlx::migrate!("./migrations/audit")
        .run(&pool)
        .await
        .expect("Failed to run migrations");

    DbHandle {
        pool,
        url: "sqlite::memory:".to_string(),
        path: None,
        freshly_created: true,
    }
}

#[tokio::test]
async fn test_insert_and_query_event() {
    let db = setup_test_db().await;

    // Create a test event
    let event = AuditEvent::new(
        Some(1),
        EventType::UserCreated {
            username: "testuser".to_string(),
        },
    )
    .with_ip_address("192.168.1.100");

    // Insert the event
    insert_audit_event(&db, &event).await.expect("Failed to insert event");

    // Query it back
    let filter = EventFilter::new().with_actor(1);
    let events = query_audit_events(&db, filter).await.expect("Failed to query events");

    assert_eq!(events.len(), 1);
    assert_eq!(events[0].actor_id, Some(1));
    assert_eq!(events[0].category, EventCategory::UserManagement);
    assert_eq!(events[0].ip_address, Some("192.168.1.100".to_string()));

    match &events[0].event_type {
        EventType::UserCreated { username } => {
            assert_eq!(username, "testuser");
        }
        _ => panic!("Wrong event type"),
    }
}

#[tokio::test]
async fn test_filter_by_category() {
    let db = setup_test_db().await;

    // Insert events from different categories
    let user_event = AuditEvent::new(
        Some(1),
        EventType::UserCreated {
            username: "alice".to_string(),
        },
    );
    insert_audit_event(&db, &user_event).await.expect("Failed to insert event");

    let group_event = AuditEvent::new(
        Some(1),
        EventType::GroupCreated {
            name: "admins".to_string(),
        },
    );
    insert_audit_event(&db, &group_event).await.expect("Failed to insert event");

    // Query by category
    let filter = EventFilter::new().with_category(EventCategory::UserManagement);
    let events = query_audit_events(&db, filter).await.expect("Failed to query events");

    assert_eq!(events.len(), 1);
    match &events[0].event_type {
        EventType::UserCreated { .. } => {}
        _ => panic!("Expected UserCreated event"),
    }
}

#[tokio::test]
async fn test_count_events() {
    let db = setup_test_db().await;

    // Insert multiple events
    for i in 0..5 {
        let event = AuditEvent::new(
            Some(1),
            EventType::UserCreated {
                username: format!("user{}", i),
            },
        );
        insert_audit_event(&db, &event).await.expect("Failed to insert event");
    }

    let filter = EventFilter::new();
    let count = count_audit_events(&db, &filter).await.expect("Failed to count events");

    assert_eq!(count, 5);
}

#[tokio::test]
async fn test_pagination() {
    let db = setup_test_db().await;

    // Insert 10 events
    for i in 0..10 {
        let event = AuditEvent::new(
            Some(1),
            EventType::UserCreated {
                username: format!("user{}", i),
            },
        );
        insert_audit_event(&db, &event).await.expect("Failed to insert event");
    }

    // Query first page
    let filter = EventFilter::new().with_limit(5).with_offset(0);
    let page1 = query_audit_events(&db, filter).await.expect("Failed to query events");
    assert_eq!(page1.len(), 5);

    // Query second page
    let filter = EventFilter::new().with_limit(5).with_offset(5);
    let page2 = query_audit_events(&db, filter).await.expect("Failed to query events");
    assert_eq!(page2.len(), 5);

    // Ensure they're different events
    assert_ne!(page1[0].id, page2[0].id);
}

#[tokio::test]
async fn test_multiple_event_types() {
    let db = setup_test_db().await;

    // Insert various event types
    let events = vec![
        EventType::UserCreated {
            username: "alice".to_string(),
        },
        EventType::UserDeleted {
            username: "bob".to_string(),
            user_id: 2,
        },
        EventType::GroupCreated {
            name: "admins".to_string(),
        },
        EventType::RelayHostCreated {
            name: "relay1".to_string(),
            endpoint: "192.168.1.1:22".to_string(),
        },
        EventType::AccessGranted {
            relay_name: "relay1".to_string(),
            relay_id: 1,
            principal_kind: "user".to_string(),
            principal_name: "alice".to_string(),
            principal_id: 1,
        },
    ];

    for event_type in events {
        let event = AuditEvent::new(Some(1), event_type);
        insert_audit_event(&db, &event).await.expect("Failed to insert event");
    }

    // Query all events
    let filter = EventFilter::new();
    let all_events = query_audit_events(&db, filter).await.expect("Failed to query events");

    assert_eq!(all_events.len(), 5);

    // Verify categories
    let categories: Vec<EventCategory> = all_events.iter().map(|e| e.category).collect();
    assert!(categories.contains(&EventCategory::UserManagement));
    assert!(categories.contains(&EventCategory::GroupManagement));
    assert!(categories.contains(&EventCategory::RelayManagement));
    assert!(categories.contains(&EventCategory::AccessControl));
}

#[tokio::test]
async fn test_session_id_filtering() {
    let db = setup_test_db().await;

    let session_id = "sess_12345";

    // Insert events with session ID
    let event1 = AuditEvent::new(
        Some(1),
        EventType::SessionStarted {
            session_id: session_id.to_string(),
            relay_name: "relay1".to_string(),
            relay_id: 1,
            username: "alice".to_string(),
            client_type: ClientType::Web,
        },
    )
    .with_session_id(session_id);

    let event2 = AuditEvent::new(
        Some(1),
        EventType::SessionEnded {
            session_id: session_id.to_string(),
            relay_name: "relay1".to_string(),
            relay_id: 1,
            username: "alice".to_string(),
            duration_ms: 60000,
            client_type: ClientType::Web,
        },
    )
    .with_session_id(session_id);

    insert_audit_event(&db, &event1).await.expect("Failed to insert event");
    insert_audit_event(&db, &event2).await.expect("Failed to insert event");

    // Query by session ID
    let mut filter = EventFilter::new();
    filter.session_id = Some(session_id.to_string());

    let events = query_audit_events(&db, filter).await.expect("Failed to query events");

    assert_eq!(events.len(), 2);
    assert!(events.iter().all(|e| e.session_id.as_deref() == Some(session_id)));
}
