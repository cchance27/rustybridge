# Logging & Audit System - Future Improvements

This document tracks potential improvements to the logging and audit system for future sprints.

## High Priority

### 1. Add `#[tracing::instrument]` to Key Functions
Add automatic span creation to critical functions for better call hierarchy visibility.

**What it does:**
- Creates DEBUG-level spans on function entry/exit
- Captures function arguments as span fields
- Provides context for nested log events
- Helps correlate errors to their call path

**Does NOT:**
- Replace your manual `info!()`, `warn!()`, `error!()` calls
- Add noise at INFO level (spans are DEBUG level by default)

**Candidates:**
- API handlers in `rb-web` (auth, sessions, CRUD operations)
- `server-core` business logic functions
- SSH session lifecycle functions in `server-core/src/ssh_server/`

---

## Medium Priority

### 2. Log Rotation / Retention for Server
If not handled by deployment infrastructure:
- Consider `tracing-appender` for file output with rotation
- Match server-side log retention to audit retention config

---

### 3. Request ID Propagation
Add a UUID to all HTTP requests for correlation:
- Generate at request entry (middleware)
- Include in all tracing spans/events for that request
- Makes debugging distributed logs much easier

---

## Lower Priority

### 4. OpenTelemetry Export
For future centralized observability (Jaeger, Datadog, etc.):
- `tracing-opentelemetry` integrates cleanly with existing setup
- Would require adding as optional dependency

---

### 5. Audit Event Streaming to External Systems
For compliance/SIEM integration:
- Add optional webhook or message queue export
- Would be a larger feature requiring design
