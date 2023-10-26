#!/usr/bin/env bash
#
# Checks the public API of crates, exits with non-zero if there are currently
# changes to the public API not already committed to in the various api/*.txt
# files.

set -e

export RUSTDOCFLAGS='-A rustdoc::broken-intra-doc-links'
REPO_DIR=$(git rev-parse --show-toplevel)
API_DIR="$REPO_DIR/api"
CMD="cargo +nightly public-api --simplified"

# cargo public-api uses nightly so the toolchain must be available.
if ! cargo +nightly --version > /dev/null; then
    echo "script requires a nightly toolchain to be installed (possibly >= nightly-2023-05-24)" >&2
    exit 1
fi

pushd "$REPO_DIR" > /dev/null
$CMD --no-default-features | sort --unique > "$API_DIR/no-default-features.txt"
$CMD --no-default-features --features=alloc | sort --unique > "$API_DIR/alloc.txt"
$CMD | sort --unique > "$API_DIR/default-features.txt"
$CMD --features=global-context | sort --unique > "$API_DIR/global-context.txt"
$CMD --all-features | sort --unique > "$API_DIR/all-features.txt"

if [[ $(git status --porcelain api) ]]; then
    echo "You have introduced changes to the public API, commit the changes to api/ currently in your working directory" >&2
else
    echo "No changes to the current public API"
fi
popd > /dev/null
