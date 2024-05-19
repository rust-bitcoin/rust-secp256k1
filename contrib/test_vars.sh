#!/usr/bin/env bash
# disable verify unused vars, despite the fact that they are used when sourced
# shellcheck disable=SC2034

# Test all these features with "std" enabled.
FEATURES_WITH_STD="hashes global-context lowmemory rand recovery serde std alloc hashes-std rand-std"

# Test all these features without "std" enabled.
FEATURES_WITHOUT_STD="hashes global-context lowmemory rand recovery serde alloc"

# Run these examples.
EXAMPLES="sign_verify:hashes-std sign_verify_recovery:hashes-std,recovery generate_keys:rand-std"
