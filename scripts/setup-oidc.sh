#!/bin/bash
# Quick OIDC setup script for testing with Google OAuth

set -e

echo "=== RustyBridge OIDC Setup ==="
echo ""
echo "This script will help you configure OIDC for testing."
echo ""

resolve_db_path() {
    # Mirror state-store default: prefer $RB_SERVER_DB_URL, otherwise XDG state/data, then ~/.local/state
    if [ -n "$RB_SERVER_DB_URL" ]; then
        local url="$RB_SERVER_DB_URL"
        if [[ "$url" =~ ^sqlite:(.*)$ ]]; then
            local path="${BASH_REMATCH[1]}"
            # Handle sqlite:///absolute/path by trimming the leading double slash
            path="${path#//}"
            echo "$path"
        else
            echo "$url"
        fi
        return
    fi

    local state_dir
    state_dir="${XDG_STATE_HOME:-${XDG_DATA_HOME:-${HOME}/.local/state}}"
    echo "$state_dir/rustybridge/server.db"
}

DB_PATH="$(resolve_db_path)"

if [ -z "$DB_PATH" ]; then
    echo "Error: Could not determine server database path."
    exit 1
fi

# Check if database exists at the resolved path
if [ ! -f "$DB_PATH" ]; then
    echo "Error: Database not found at $DB_PATH"
    echo "Please run the server at least once to create the database."
    exit 1
fi

echo "Using server database: $DB_PATH"

echo "Enter your OIDC provider details:"
echo ""

# Prompt for provider type
echo "Select OIDC provider:"
echo "1) Google OAuth"
echo "2) Custom (Authelia, Keycloak, etc.)"
read -p "Choice [1]: " PROVIDER_CHOICE
PROVIDER_CHOICE=${PROVIDER_CHOICE:-1}

if [ "$PROVIDER_CHOICE" = "1" ]; then
    ISSUER_URL="https://accounts.google.com"
    echo "Using Google OAuth"
    echo "Issuer URL: $ISSUER_URL"
else
    read -p "Issuer URL (e.g., http://localhost:9091): " ISSUER_URL
fi

echo ""
read -p "Client ID: " CLIENT_ID
read -p "Client Secret: " CLIENT_SECRET
read -p "Redirect URL [http://localhost:8080/api/auth/oidc/callback]: " REDIRECT_URL
REDIRECT_URL=${REDIRECT_URL:-http://localhost:8080/api/auth/oidc/callback}

echo ""
echo "Configuring OIDC with:"
echo "  Issuer URL: $ISSUER_URL"
echo "  Client ID: $CLIENT_ID"
echo "  Client Secret: ****"
echo "  Redirect URL: $REDIRECT_URL"
echo ""

read -p "Proceed? [y/N]: " CONFIRM
if [ "$CONFIRM" != "y" ] && [ "$CONFIRM" != "Y" ]; then
    echo "Aborted."
    exit 0
fi

# Insert into database
sqlite3 "$DB_PATH" <<EOF
INSERT OR REPLACE INTO server_options (key, value) VALUES 
  ('oidc_issuer_url', '$ISSUER_URL'),
  ('oidc_client_id', '$CLIENT_ID'),
  ('oidc_client_secret', '$CLIENT_SECRET'),
  ('oidc_redirect_url', '$REDIRECT_URL');
EOF

echo ""
echo "✓ OIDC configuration saved!"
echo ""
echo "Next steps:"
echo "1. Start the server: ./run_web.sh"
echo "2. Open browser to: http://localhost:8080/api/auth/oidc/login"
echo ""
