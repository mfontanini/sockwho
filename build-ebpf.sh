#!/bin/bash

set -e

cd sockwho-ebpf
cargo +nightly build \
  --target bpfel-unknown-none \
  -Z build-std=core \
  $@
