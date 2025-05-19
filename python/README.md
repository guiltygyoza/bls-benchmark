# Python BLS Signature Verification Benchmark

This directory contains the Python implementation of the BLS signature verification benchmark for Ethereum attestations.

## Overview

The benchmark measures how many BLS signatures can be verified per second using the BLS12-381 curve implementation, which is the cryptographic scheme used in Ethereum 2.0 (Eth2) for validator attestations.

## Requirements

- Python 3.7+
- Dependencies listed in `requirements.txt`

## Installation

Install the required dependencies:

```bash
pip install -r requirements.txt
```

## Usage

Run the benchmark script:

```bash
python bls_benchmark.py
```

## Performance

In our testing, this Python implementation achieves approximately 3.13 verifications per second. This is significantly slower than the Go implementation, which demonstrates the performance difference between interpreted and compiled languages for cryptographic operations.

## Features

The benchmark includes:
- Generation of random Ethereum attestation data
- BLS key pair generation
- Signature creation and verification
- Multiple trials for statistical significance
- Performance metrics including average, median, and standard deviation

## Customization

You can modify the benchmark parameters in the `main()` function:
- `num_attestations`: Number of test attestations to generate
- `trial_duration`: Duration of each benchmark trial in seconds
- `num_trials`: Number of trials to run

## Technical Details

The benchmark uses:
- `py-ecc` library for BLS12-381 curve operations
- A simplified Ethereum attestation data structure
- G2ProofOfPossession scheme for BLS signatures (as used in Ethereum)

## Limitations

This Python implementation is primarily for educational purposes and reference. For production use or higher performance, consider using the Go implementation or other optimized libraries.
