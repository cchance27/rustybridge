#!/usr/bin/env bash

cargo sort --workspace
cargo +nightly fmt
cargo clippy --fix --allow-dirty --allow-staged --message-format=short

# Check for unused dependencies in rb-web (wasm target)
cargo +nightly udeps -p rb-web --features web --no-default-features --target wasm32-unknown-unknown --quiet

# Check for unused dependencies in rb-web (server target)
cargo +nightly udeps -p rb-web --features server --no-default-features --quiet

# Check for unused dependencies in rb-cli (rb server)
cargo +nightly udeps -p rb-cli --bin rb-server --features rb-server --quiet

# Check for unused dependencies in rb-cli (rb client)
cargo +nightly udeps -p rb-cli --bin rb --features rb --quiet