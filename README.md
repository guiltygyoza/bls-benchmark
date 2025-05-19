# BLS Signature Verification Benchmark

This repository contains benchmarks for BLS (Boneh-Lynn-Shacham) signature verification of Ethereum attestations implemented in different programming languages.

## Overview

The benchmarks measure how many BLS signatures can be verified per second using the BLS12-381 curve implementation, which is the cryptographic scheme used in post-merge Ethereum for validator attestations.

## Implementations

The repository contains the following implementations:

- [Go Implementation](./go/): Uses the `herumi/bls-eth-go-binary` library
- [Python Implementation](./python/): Uses the `py-ecc` library
- [Rust Implementation](./rust/): Uses the `blst` library

## Performance Comparison

| Implementation | Verifications/second | Notes |
|----------------|----------------------|-------|
| Rust           | ~1421                | Fastest due to compiled language and highly optimized BLST library |
| Go             | ~1079                | Fast due to compiled language and optimized library |
| Python         | ~3.13                | Slower due to interpreted language and pure Python implementation |

## Repository Structure

```
.
├── go/                  # Go implementation
│   ├── bls_benchmark.go # Go benchmark code
│   └── README.md        # Go-specific documentation
│
├── python/              # Python implementation
│   ├── bls_benchmark.py # Python benchmark code
│   ├── requirements.txt # Python dependencies
│   └── README.md        # Python-specific documentation
│
└── rust/                # Rust implementation
    ├── src/main.rs      # Rust benchmark code
    ├── Cargo.toml       # Rust dependencies
    └── README.md        # Rust-specific documentation
```

## Getting Started

See the README files in each implementation directory for specific instructions on how to run the benchmarks.

## License

MIT
