#!/usr/bin/env bash

set -ex

REPO_DIR=$(git rev-parse --show-toplevel)

$REPO_DIR/contrib/_test.sh
