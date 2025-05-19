#!/usr/bin/env python3
"""
BLS Signature Verification Benchmark for Ethereum Attestations

This script benchmarks how many BLS signatures of Ethereum attestations
can be verified per second on the current machine.
"""

import time
import random
import statistics
from typing import List, Tuple
from dataclasses import dataclass

from py_ecc.bls import G2ProofOfPossession as bls
from py_ecc.bls.g2_primitives import G1_to_pubkey, G2_to_signature
from py_ecc.optimized_bls12_381 import G1, G2, Z1, Z2

# Simplified Ethereum attestation data structure
@dataclass
class AttestationData:
    slot: int
    index: int
    beacon_block_root: bytes
    source_epoch: int
    source_root: bytes
    target_epoch: int
    target_root: bytes

    def serialize(self) -> bytes:
        """Serialize the attestation data to bytes for signing"""
        return b''.join([
            self.slot.to_bytes(8, 'little'),
            self.index.to_bytes(8, 'little'),
            self.beacon_block_root,
            self.source_epoch.to_bytes(8, 'little'),
            self.source_root,
            self.target_epoch.to_bytes(8, 'little'),
            self.target_root
        ])

def generate_random_bytes(length: int) -> bytes:
    """Generate random bytes of specified length"""
    return bytes(random.getrandbits(8) for _ in range(length))

def generate_keypair() -> Tuple[int, bytes]:
    """Generate a BLS keypair (private key, public key)"""
    private_key = bls.KeyGen(generate_random_bytes(32))
    public_key = bls.SkToPk(private_key)
    return private_key, public_key

def generate_test_attestations(count: int) -> List[Tuple[AttestationData, bytes, bytes]]:
    """
    Generate test attestations with valid signatures
    Returns a list of (attestation_data, signature, public_key) tuples
    """
    attestations = []
    
    for _ in range(count):
        # Generate random attestation data
        attestation = AttestationData(
            slot=random.randint(0, 2**32),
            index=random.randint(0, 2**16),
            beacon_block_root=generate_random_bytes(32),
            source_epoch=random.randint(0, 2**32),
            source_root=generate_random_bytes(32),
            target_epoch=random.randint(0, 2**32),
            target_root=generate_random_bytes(32)
        )
        
        # Generate a keypair and sign the attestation
        private_key, public_key = generate_keypair()
        message = attestation.serialize()
        signature = bls.Sign(private_key, message)
        
        attestations.append((attestation, signature, public_key))
    
    return attestations

def run_verification_benchmark(attestations: List[Tuple[AttestationData, bytes, bytes]], 
                              duration_seconds: int = 5) -> int:
    """
    Run a benchmark verifying BLS signatures for the given duration
    Returns the number of verifications performed
    """
    count = 0
    end_time = time.time() + duration_seconds
    
    # Keep verifying signatures until the time is up
    while time.time() < end_time:
        # Get an attestation from the list (cycling through them)
        attestation, signature, public_key = attestations[count % len(attestations)]
        message = attestation.serialize()
        
        # Verify the signature
        assert bls.Verify(public_key, message, signature)
        
        count += 1
    
    return count

def main():
    print("BLS Signature Verification Benchmark for Ethereum Attestations")
    print("=" * 70)
    
    # Parameters
    num_attestations = 100  # Number of test attestations to generate
    trial_duration = 5      # Duration of each trial in seconds
    num_trials = 3          # Number of trials to run
    
    print(f"Generating {num_attestations} test attestations...")
    attestations = generate_test_attestations(num_attestations)
    print("Test attestations generated successfully.")
    
    # Run benchmark trials
    results = []
    print(f"\nRunning {num_trials} benchmark trials (each {trial_duration} seconds):")
    
    for i in range(num_trials):
        print(f"  Trial {i+1}/{num_trials}... ", end="", flush=True)
        verifications = run_verification_benchmark(attestations, trial_duration)
        verifications_per_second = verifications / trial_duration
        results.append(verifications_per_second)
        print(f"{verifications_per_second:.2f} verifications/second")
    
    # Calculate and display statistics
    avg_verifications = statistics.mean(results)
    median_verifications = statistics.median(results)
    stdev_verifications = statistics.stdev(results) if len(results) > 1 else 0
    
    print("\nResults:")
    print(f"  Average: {avg_verifications:.2f} verifications/second")
    print(f"  Median:  {median_verifications:.2f} verifications/second")
    print(f"  Std Dev: {stdev_verifications:.2f}")
    
    # Individual trial results
    print("\nIndividual trial results (verifications/second):")
    for i, result in enumerate(results):
        print(f"  Trial {i+1}: {result:.2f}")

if __name__ == "__main__":
    main()
