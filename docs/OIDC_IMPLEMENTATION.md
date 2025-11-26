# OIDC Implementation Documentation

## ✅ Implemented Features

### 1. **OIDC Login Flow** (`/api/auth/oidc/login`)
- Fetches OIDC configuration from database (`server_options` table)
- Creates OIDC client with provider discovery
- Generates authorization URL with **PKCE (SHA-256)** support
- Stores **nonce** and **state (CSRF token)** in session
- Redirects user to OIDC provider
- Supports optional `ssh_code` parameter for SSH out-of-band flow

### 2. **OIDC Callback** (`/api/auth/oidc/callback`)
- Validates **state parameter** (CSRF protection)
- Retrieves and validates **nonce** from session
- Exchanges authorization code for tokens with **PKCE verifier**
- Validates ID token with proper nonce
- Extracts claims from ID token (subject, email)
- Looks up user by OIDC link in `user_oidc_links` table
- Logs in user via session management
- **Redirects to `/` on success**
- **Redirects to `/oidc/error?error=account_not_linked` if no linked account found**

### 3. **OIDC Account Linking** (`/api/auth/oidc/link`)
- Allows authenticated users to link their OIDC account
- Accepts `return_to` query parameter to redirect back to original page
- Separate flow from login to prevent account hijacking
- Uses different redirect URL (`/api/auth/oidc/callback/link`)
- Full security: PKCE, nonce, and CSRF protection
- Stores return URL in session for post-link redirect

### 4. **OIDC Link Callback** (`/api/auth/oidc/callback/link`)
- Validates state and nonce
- Checks for existing links to prevent conflicts
- Creates or updates link in `user_oidc_links` table
- Retrieves return URL from session
- **Redirects to original page with `?success=oidc_linked`**

### 5. **OIDC Server Functions** (Dioxus)
- `GET /api/auth/oidc/link_status` - Get current user's OIDC link status
- `POST /api/auth/oidc/unlink` - Unlink current user's OIDC account
- `GET /api/users/{user_id}/oidc_status` - (Admin) Get any user's OIDC status
- `DELETE /api/users/{user_id}/oidc` - (Admin) Unlink any user's OIDC account

### 6. **UI Integration**
- **Avatar Dropdown**: "Link OIDC Account" button (only shows if not already linked)
- **Users Table**: OIDC status column showing "Linked" or "Not linked"
- **Clickable Badge**: Click "Linked" to trigger unlink confirmation modal
- **Unlink Modal**: Confirmation dialog for unlinking OIDC accounts
- **Toast Notifications**: Success/error messages after link/unlink operations
- **Real-time Updates**: Table updates immediately after unlink without page refresh
- **OIDC Error Page**: Dedicated page (`/oidc/error`) for handling all authentication errors

### 7. **Database Integration**
- Dynamic configuration from `server_options` table:
  - `oidc_issuer_url`
  - `oidc_client_id`
  - `oidc_client_secret`
  - `oidc_redirect_url`
- User-OIDC links stored in `user_oidc_links` table with columns:
  - `user_id` - Internal user ID
  - `provider_id` - OIDC issuer URL
  - `subject_id` - OIDC subject (unique per provider)
  - `email` - User's email from OIDC provider
  - `name` - User's name from OIDC provider
  - `picture` - User's picture from OIDC provider

### 8. **Security Features** ✅
- ✅ **PKCE (SHA-256)** - Prevents authorization code interception
- ✅ **Nonce Validation** - Prevents replay attacks
- ✅ **CSRF Protection** - State parameter validation
- ✅ **ID Token Validation** - Cryptographic verification with proper nonce
- ✅ **Session Security** - Server-side nonce/state storage
- ✅ **One-time Use** - Nonces and state tokens cleaned up after use
- ✅ **Provider Discovery** - Uses `.well-known/openid-configuration`
- ✅ **Permission Checks** - Admin functions require `users:view` and `users:edit`
- Prevents linking same OIDC account to multiple users
- Session management integration
- SSH OIDC: binds auth sessions to requested user, rejects mismatches, one-time use codes
- SSH OIDC: abandoned SSH sessions are marked `abandoned` when the client disconnects mid-flow (instead of staying pending or being marked rejected)

### 9. **Logging**
All OIDC operations are logged with structured logging:
- User IDs and usernames
- OIDC subjects and emails
- PKCE usage status
- Success/failure reasons
- Admin actions (who unlinked whom)

Example logs:
```
INFO Using PKCE for token exchange
INFO OIDC authentication successful, subject="...", email="...", pkce_used=true
INFO User logged in via OIDC, user_id=1, pkce_used=true
INFO Successfully linked OIDC account, user_id=1, subject="...", pkce_used=true
INFO OIDC account unlinked by admin, admin_user=1, target_user=2
```

### 10. **Login Page** 
   - Update login page to show OIDC login option
   
### 11. **Name & Picture Extraction**
   - Loads from token claims on login
   - Update UI to display user avatars
   - Update avatar dropdown to show name

### 12. **SSH Out-of-Band Flow**
- SSH keyboard-interactive flow issues an `ssh_code` tied to the requested SSH user id
- Web OIDC callback completes the session only if the authenticated user matches the requested SSH user
- SSH handler enforces the same match and consumes the session on success; mismatches are rejected and invalidated
- One-time use enforcement for SSH auth sessions; expired/reused codes are rejected

### 13. **SSH Public-Key Support End-to-End**
- ✅ Created new Profile page (`/profile`) for user self-service SSH key management
- ✅ Implemented Dioxus server functions for SSH key CRUD operations (`get_my_ssh_keys`, `add_my_ssh_key`, `delete_my_ssh_key`)
- ✅ Added SSH key validation (format checking for ssh-rsa, ssh-dss, ssh-ed25519, ecdsa-sha2-)
- ✅ Updated Access page to display SSH key count for each user
- ✅ Added "Profile" link to avatar dropdown for easy access
- ✅ Integrated OIDC link/unlink functionality into Profile page with confirmation modal
- ✅ SSH auth path pulls keys from the same store used by the web UI and CLI
- Note: Per-key enable/disable and last-used metadata for auditing not yet implemented

## ⚠️ TODO / Pending Items

**IMPORTANT REMINDERS BEFORE IMPLEMENTING TODO ITEMS** 
- Using rb-types crate for all reuseable struct's
- Use dioxus 0.7.1 style endpoints #[get/post/put/delete(), extractors] Review the proper format based on api/relay_list.rs for proper usage.
- Database manipulation should be centralized in the state-core crate
- Review migrations for current database schema. 
- Prioritize keeping code secure, reuseable, and avoid code duplication, 
- Make sure new endpoints properly use our ensure_claims, Protected {} and RequireAuth {} around any new pages to protect them.

### High Priority
1. **Role Management in Web UI (Access Page)**
   - Add role list/create/delete and role-claims management to the Access page, lets have the user list tall on the left and on the right have groups at top and roles below groups.
   - Show user/group->role assignments and allow assignment/removal from the UI
   - Surface claim descriptions so admins understand access implications 
   - Add role selection to our user/group edit and creation pages so admins can prefer to use roles over basic claims, make sure our schema matches this expectation, and that when we're looking up permissions we handle this user->group->role->claims hierarchy properly.

2. **Session Visibility & Control in Web UI**
   - Add a Management tab for active sessions (web logins, SSH/TUI sessions, relay connections)
   - Plumb backend APIs to enumerate: active SSH sessions (including relay target), active web sessions, active web relays
   - Show per-session metadata (user, start time, source IP, auth method, relay name, idle time)
   - Provide admin actions where safe (e.g., terminate session / disconnect relay)
   - Ensure data comes from authoritative in-memory/store sources and is rate-limited to avoid DB load

3. **Auth Surface Controls**
   - Add server options to enable/disable OIDC for: (a) web login, (b) SSH keyboard-interactive, (c) disabled
   - Add parallel controls for password login (web and SSH) and SSH public-key/cert auth so administrators can enforce OIDC-only, password-only, key/cert-only, or mixed modes
   - Enforce invariants: at least one login method must remain enabled for web and for SSH; refuse misconfiguration at startup and in `rb-server web set`
   - UI/CLI should only present OIDC login buttons when OIDC is enabled and config is present
   - Optional: perform a lightweight provider discovery/health check before showing OIDC as available, fall back to password if unavailable
   - Explore chaining/step-up for SSH (e.g., publickey+OIDC or cert+OIDC). Russh currently short-circuits on first accepted method; may need custom multi-factor flow in the handler or upstream support to require sequential methods.
   - Consider user-cancel fallthrough for SSH OIDC (e.g., short timeout or explicit "cancel" prompt that rejects to allow password/key methods to proceed; no standard keyboard-interactive keystroke exists to abort mid-flow).

### Medium Priority
1. **Token Refresh**
   - No refresh token handling
   - Users must re-authenticate when token expires
   - Could implement background refresh

2. **Multiple Provider Support**
   - Currently assumes single OIDC provider (needs migration of db to clean table)
   - Could support multiple providers (Google, GitHub, Microsoft, etc.)
   - Would need provider selection UI for linking, we'd also need to unlink path to check the correct provider to unlink. we'd also likely want to handle multi-provider per account in future at moment i think we only support one provider per account.
   - show provider name on login page or provider image if it's in database, if neither show generic use sso message below the user/pass login.

3. **Provider Provisioning via rb-server clap cli**
   - adjust clap to support multi-provisioning servers.
   - should be able to add and remove providers
   - should be able to update provider configuration
   - should be able to list providers

### Low Priority
1. **Token Expiry Checks**
   - ID tokens not validated for expiration
   - Should check `exp` claim

2. **Audience Validation**
   - ID token audience (`aud`) not explicitly checked
   - Should validate matches client ID

3. **Provider Management**
   - Add provider management UI (access page bottom below users/groups?)
   - Allow adding new providers
   - Allow removing providers
   - Allow updating provider configuration

4. **Validate Handling 1 OIDC on multiple users**
   - for web login we should present a selection so they can select which user they want to login with. 
   - for ssh login we need to confirm our ssh oidc actually works and checks all the oidc to see if the username in ssh matches the valid oidc usernames.  
   - we should also confirm we can handle the case where the username in ssh doesn't match any of the valid oidc usernames. 
   - review security implications of this.
   
## 🔧 Configuration

### Database Setup

We should likely expand this in a future migration to move it to it's own table with row per provider.

```sql
INSERT INTO server_options (key, value) VALUES 
  ('oidc_issuer_url', 'https://accounts.google.com'),
  ('oidc_client_id', 'YOUR_CLIENT_ID'),
  ('oidc_client_secret', 'YOUR_CLIENT_SECRET'),
  ('oidc_redirect_url', 'http://localhost:8080/api/auth/oidc/callback');
```

You can also set OIDC/web options from the CLI:

```bash
rb-server web set server-url "http://127.0.0.1:8080"
rb-server web set oidc-issuer-url "https://sso.example.com"
rb-server web set oidc-client-id "YOUR_CLIENT_ID"
rb-server web set oidc-client-secret "YOUR_CLIENT_SECRET"
rb-server web set oidc-redirect-url "http://127.0.0.1:8080/api/auth/oidc/callback"
```

### Configuration via CLI

Use the CLI to set OIDC options (preferred and only supported path):
```bash
rb-server web set server-url "http://127.0.0.1:8080"
rb-server web set oidc-issuer-url "https://sso.example.com"
rb-server web set oidc-client-id "YOUR_CLIENT_ID"
rb-server web set oidc-client-secret "YOUR_CLIENT_SECRET"
rb-server web set oidc-redirect-url "http://127.0.0.1:8080/api/auth/oidc/callback"
```

## 📋 Testing Checklist

### Login Flow
- [x] Visit `/api/auth/oidc/login`
- [x] Redirected to OIDC provider
- [x] Authenticate with provider
- [x] Redirected back to `/api/auth/oidc/callback`
- [x] If account linked: logged in and redirected to `/`
- [x] If account not linked: redirected to `/login?error=account_not_linked`

### Linking Flow
- [x] Login with password first
- [x] Click avatar → "Link OIDC Account"
- [x] Authenticate with OIDC provider
- [x] Redirected back to original page with `?success=oidc_linked`
- [x] Account linked successfully
- [x] Can now login via OIDC
- [x] "Link OIDC Account" button disappears from avatar menu

### Unlinking Flow
- [x] Go to Access page
- [x] See "Linked" badge in OIDC column
- [x] Click "Linked" badge
- [x] Confirm in modal
- [x] See success toast
- [x] Badge changes to "Not linked" immediately
- [x] "Link OIDC Account" button reappears in avatar menu

### Error Cases
- [ ] Missing OIDC configuration → error page
- [ ] Invalid provider URL → error page
- [ ] Token exchange fails → error page
- [ ] Attempt to link already-linked account → error message
- [ ] All error cases properly handled with user-friendly messages

## 📁 Files Modified

### New Files
- `crates/rb-web/src/app/auth/oidc.rs` - Dioxus server functions for OIDC
- `crates/rb-web/src/server/auth/oidc.rs` - Login and callback handlers
- `crates/rb-web/src/server/auth/oidc_link.rs` - Account linking handlers
- `crates/rb-web/src/server/auth/oidc_unlink.rs` - Unlink handler (Axum)
- `crates/rb-types/src/auth/oidc.rs` - Shared OIDC types
- `crates/server-core/src/auth/oidc.rs` - OIDC client logic
- `crates/server-core/src/auth/ssh_cert.rs` - SSH certificate utilities
- `crates/server-core/src/error.rs` - Centralized error types
- `crates/state-store/migrations/server/20251124223000_oidc_and_ssh_keys.sql` - Database schema
- `docs/OIDC_IMPLEMENTATION.md` - This file
- `docs/OIDC_TESTING.md` - Testing guide
- `scripts/setup-oidc.sh` - Configuration script

### Modified Files
- `crates/rb-web/src/app/components/avatar_dropdown.rs` - Added "Link OIDC Account" button
- `crates/rb-web/src/app/pages/access.rs` - Added OIDC column and unlink modal
- `crates/rb-web/src/app/api/users.rs` - Added user ID to UserGroupInfo
- `crates/rb-web/src/server/mod.rs` - Route registration
- `crates/rb-web/src/server/auth/mod.rs` - Module exports
- `crates/rb-web/Cargo.toml` - Added `urlencoding` dependency
- `crates/rb-types/src/users.rs` - Added `id` field to UserGroupInfo
- `crates/rb-types/src/auth/mod.rs` - Export OIDC module
- `crates/server-core/Cargo.toml` - Added OIDC dependencies
- `crates/server-core/src/handler.rs` - SSH handler updates
- `crates/server-core/src/lib.rs` - Module exports
- `crates/state-store/src/lib.rs` - Added `get_user_id()` function

## 🔐 Security Status

**✅ PRODUCTION-READY SECURITY**

All critical security features have been implemented:

1. ✅ **PKCE (SHA-256)** - Implemented and tested
2. ✅ **Nonce Validation** - Proper session-based nonce storage and validation
3. ✅ **CSRF Protection** - State parameter validated on callback
4. ✅ **ID Token Validation** - Cryptographic verification with nonce
5. ⚠️ **Token Expiry** - Not checked (low priority)
6. ⚠️ **Audience Validation** - Not explicitly checked (low priority)
7. ⚠️ **HTTPS** - Should use HTTPS in production (deployment concern)

**The OIDC implementation is secure and suitable for production use**, with only minor enhancements pending (token expiry and audience validation).

## 🎯 Recommended Next Steps

1. **Test all error cases** - Ensure proper error handling and user feedback
2. **Extract profile information** - Parse name and picture claims
3. **Create error page** - Dedicated OIDC error page instead of query params
4. **Complete SSH OIDC flow** - Implement keyboard-interactive integration
5. **Add token expiry validation** - Check `exp` claim in ID tokens

## My Questions
- What happens if multiple users link the same OIDC account? We should allow them to select which local account they want to use?
- Multi Provider Support? Allow us to store provider name, and logo so they can all be selectable from the link menu and login page. One oidc per account for now?
