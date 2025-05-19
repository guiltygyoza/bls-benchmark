# Rust BLS Signature Verification Benchmark

This directory contains the Rust implementation of the BLS signature verification benchmark for Ethereum attestations.

## Overview

The benchmark measures how many BLS signatures can be verified per second using the BLS12-381 curve implementation, which is the cryptographic scheme used in Ethereum for validator attestations.

## Requirements

- Rust 1.60+ and Cargo
- Rust toolchain (install via [rustup](https://rustup.rs/))

## Installation

The Cargo package manager will automatically download the required dependencies when you build or run the program.

```bash
# Clone the repository (if you haven't already)
git clone https://github.com/yourusername/bls-experiment.git
cd bls-experiment/rust

# Build the benchmark
cargo build --release
```

## Usage

Run the benchmark from this directory:

```bash
cargo run --release
```

Or run the executable directly after building:

```bash
./target/release/bls-benchmark
```

## Performance

In our testing, this Rust implementation achieves approximately 1421 verifications per second, which is significantly faster than both the Go implementation (~1079 verifications/second) and the Python implementation (~3.13 verifications/second).

## Features

The benchmark includes:
- Individual signature verification
- Batch verification with different batch sizes (1, 10, 50, 100)
- Multiple trials for statistical significance
- Performance metrics including average, median, and standard deviation

## Customization

You can modify the benchmark parameters in the `main()` function:
- `num_attestations`: Number of test attestations to generate
- `trial_duration`: Duration of each benchmark trial in seconds
- `num_trials`: Number of trials to run
- `batch_sizes`: Array of batch sizes to test for batch verification

## Technical Details

The benchmark uses:
- `blst` crate for BLS12-381 curve operations
- A simplified Ethereum attestation data structure
- BLS signature scheme compatible with Ethereum
