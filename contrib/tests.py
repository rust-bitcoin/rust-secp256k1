#!/usr/bin/env python3

import itertools
import subprocess
import sys
import os
from pathlib import Path

FEATURES = ['rand-std', 'recovery', 'endomorphism', 'lowmemory', 'serde']
MSRV = 1.22
RUSTC = None


def call(command, cwd):
    print(command)
    try:
        assert subprocess.check_call(command, shell=True, cwd=str(cwd)) == 0
    except subprocess.CalledProcessError as e:
        print('Execution failed, error:', e.returncode, file=sys.stderr)
        exit(e.returncode)


def set_rustc():
    global RUSTC
    try:
        RUSTC = str(subprocess.check_output(["rustc", "--version"]))
    except subprocess.CalledProcessError as e:
        print('Execution failed, error:', e, file=sys.stderr)
        exit(e.returncode)


def is_nightly():
    global RUSTC
    assert RUSTC
    return "nightly" in RUSTC


def is_stable():
    global RUSTC
    global MSRV
    assert RUSTC
    return "nightly" not in RUSTC \
           and "beta" not in RUSTC \
           and str(MSRV) not in RUSTC


def is_linux():
    return "linux" in sys.platform


def test_features(features, cwd, release=""):
    assert type(features) is list
    print('Running Tests')
    # Get all feature combinations
    for i in range(len(features) + 1):
        for feature_set in itertools.combinations(features, i):
            feature_set = ', '.join(feature_set)
            # Check that all features work even without the std feature.
            call('cargo build {} --verbose --no-default-features --features="{}"'.format(release, feature_set), cwd)
            # Check that all tests pass with all features.
            call('cargo test {} --verbose --features="{}"'.format(release, feature_set), cwd)
            # Check that fuzztarget compiles + links (tests won't pass) with all features.
            call('cargo test {} --verbose --no-run --features="fuzztarget, {}"'.format(release, feature_set), cwd)
            print()


def run_examples(cwd, features=None):
    print('Running Examples')
    features = ', '.join(features)
    # Get all examples in the examples dir
    for example in os.scandir(str(cwd.joinpath("examples").resolve())):
        if example.is_file() and example.path.endswith('.rs'):
            # Enable all features, as some examples need specific features(ie recovery and rand)
            call('cargo run  --verbose --example {} --features="{}"'.format(Path(example.name).stem, features), cwd)


def run_doc(cwd, features):
    features = ', '.join(features)
    call('cargo doc --verbose --features="{}"'.format(features), cwd)


def install_web(cwd):
    call("CARGO_TARGET_DIR=cargo_web cargo install --verbose --force cargo-web", cwd)


def test_web(cwd):
    call("cargo web build --verbose --target=asmjs-unknown-emscripten", cwd)
    call("cargo web test --verbose --target=asmjs-unknown-emscripten", cwd)


def main():
    set_rustc()
    main_features = ['rand-std', 'recovery', 'endomorphism', 'lowmemory', 'serde']
    sys_features = ['recovery', 'endomorphism', 'lowmemory']
    dir_path = Path(__file__).absolute().parent
    main_path = dir_path.parent
    sys_path = main_path.joinpath("secp256k1-sys")

    test_features(main_features, main_path)
    test_features(main_features, main_path, '--release')
    test_features(sys_features, sys_path)
    test_features(sys_features, sys_path, '--release')
    run_examples(main_path, main_features)

    # test benchmarks
    if is_nightly():
        call("cargo test --verbose --benches --features=unstable, recovery", main_path)
    # test cargo doc
    elif is_stable():
        run_doc(main_path, main_features)
        run_doc(sys_path, sys_features)

    # test no-std
    if is_nightly() and is_linux():
        path = main_path.joinpath("no_std_test")
        call('cargo run --verbose --release | grep -q "Verified Successfully"', path)

    # tes cargo web
    if is_stable() and is_linux():
        install_web(main_path)
        test_web(main_path)
        test_web(sys_path)


if __name__ == '__main__':
    main()
