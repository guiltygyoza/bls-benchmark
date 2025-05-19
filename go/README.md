# Go BLS Signature Verification Benchmark

This directory contains the Go implementation of the BLS signature verification benchmark for Ethereum attestations.

## Overview

The benchmark measures how many BLS signatures can be verified per second using the BLS12-381 curve implementation, which is the cryptographic scheme used in Ethereum 2.0 (Eth2) for validator attestations.

## Requirements

- Go 1.16+

## Installation

The Go module system will automatically download the required dependencies when you build or run the program.

## Usage

Run the benchmark from this directory:

```bash
go run bls_benchmark.go
```

Or build and then run the executable:

```bash
go build bls_benchmark.go
./bls_benchmark
```

## Performance

In our testing, this Go implementation achieves approximately 1079 verifications per second, which is significantly faster than the Python implementation (which achieved only about 3.13 verifications per second).

## Features

The benchmark includes:
- Individual signature verification
- Simulated batch verification with different batch sizes
- Multiple trials for statistical significance
- Performance metrics including average, median, and standard deviation

## Customization

You can modify the benchmark parameters in the `main()` function:
- `numAttestations`: Number of test attestations to generate
- `trialDuration`: Duration of each benchmark trial in seconds
- `numTrials`: Number of trials to run
- `batchSizes`: Array of batch sizes to test for batch verification

## Technical Details

The benchmark uses:
- `github.com/herumi/bls-eth-go-binary/bls` library for BLS12-381 curve operations
- A simplified Ethereum attestation data structure
- ETH mode Draft07 (compatible with Ethereum 2.0)
