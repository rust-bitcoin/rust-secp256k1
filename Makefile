xargo:
	RUST_TARGET_PATH=$(shell pwd) xargo build -v --target x86_64-unknown-linux-sgx

test:
	cargo test

build:
	cargo build

