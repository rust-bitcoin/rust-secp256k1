# No shebang, this file should not be executed.
# shellcheck disable=SC2148
#
# disable verify unused vars, despite the fact that they are used when sourced
# shellcheck disable=SC2034

# Test all these features with "std" enabled.
FEATURES_WITH_STD="hashes global-context global-context-less-secure lowmemory rand recovery serde"

# Test all these features without "std" enabled.
FEATURES_WITHOUT_STD="hashes global-context global-context-less-secure lowmemory rand recovery serde alloc"

# Run these examples.
EXAMPLES="sign_verify:hashes,std sign_verify_recovery:hashes,std,recovery generate_keys:rand,std"
