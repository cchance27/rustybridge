#!/usr/bin/env sh

# throw error if env variables RB_SERVER_SECRETS_KEY or RB_SERVER_SECRETS_PASSPHRASE is not set
if [ -z "$RB_SERVER_SECRETS_KEY" ] && [ -z "$RB_SERVER_SECRETS_PASSPHRASE" ]; then
    echo "Error: RB_SERVER_SECRETS_KEY or RB_SERVER_SECRETS_PASSPHRASE is not set"
    exit 1
else
    echo "RB_SERVER_SECRET_* is set"
fi

## FIXME: We currently always build dx bundle as release, because we don't know why the debug 
## mode causes our websockets to ssh to fail to try to connect after the browser has been running for a while, in release mode it seems to work fine.

tailwindcss -i ./crates/rb-web/tailwind.css -o ./crates/rb-web/assets/tailwind.css

# check for --release flag
if [ "$1" != "--release" ]; then
    dx bundle --platform web --release --package rb-web --out-dir target/debug
    cargo run -p rb-cli --bin rb-server --features rb-server -- --web
else
    dx bundle --platform web --release --package rb-web --out-dir target/release
    cargo run -p rb-cli --bin rb-server --release --features rb-server -- --web
fi