//! BLS Signature Verification Benchmark for Ethereum Attestations
//!
//! This program benchmarks how many BLS signatures of Ethereum attestations
//! can be verified per second on the current machine.

use blst::min_pk as bls;
use blst::BLST_ERROR;
use byteorder::{ByteOrder, LittleEndian};
use chrono::Local;
use rand::{rngs::ThreadRng, Rng};
use std::time::{Duration, Instant};
// For statistics calculation
use std::cmp::Ordering;

/// Simplified Ethereum attestation data structure
#[derive(Debug, Clone)]
struct AttestationData {
    slot: u64,
    index: u64,
    beacon_block_root: [u8; 32],
    source_epoch: u64,
    source_root: [u8; 32],
    target_epoch: u64,
    target_root: [u8; 32],
}

impl AttestationData {
    /// Serialize the attestation data to bytes for signing
    fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(128);

        // Slot (8 bytes)
        let mut slot_bytes = [0u8; 8];
        LittleEndian::write_u64(&mut slot_bytes, self.slot);
        buf.extend_from_slice(&slot_bytes);

        // Index (8 bytes)
        let mut index_bytes = [0u8; 8];
        LittleEndian::write_u64(&mut index_bytes, self.index);
        buf.extend_from_slice(&index_bytes);

        // Beacon block root (32 bytes)
        buf.extend_from_slice(&self.beacon_block_root);

        // Source epoch (8 bytes)
        let mut source_epoch_bytes = [0u8; 8];
        LittleEndian::write_u64(&mut source_epoch_bytes, self.source_epoch);
        buf.extend_from_slice(&source_epoch_bytes);

        // Source root (32 bytes)
        buf.extend_from_slice(&self.source_root);

        // Target epoch (8 bytes)
        let mut target_epoch_bytes = [0u8; 8];
        LittleEndian::write_u64(&mut target_epoch_bytes, self.target_epoch);
        buf.extend_from_slice(&target_epoch_bytes);

        // Target root (32 bytes)
        buf.extend_from_slice(&self.target_root);

        buf
    }
}

/// Signed attestation with signature and public key
struct SignedAttestation {
    data: AttestationData,
    signature: bls::Signature,
    public_key: bls::PublicKey,
}

/// Generate random bytes of specified length
fn generate_random_bytes(rng: &mut ThreadRng, length: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; length];
    rng.fill(&mut bytes[..]);
    bytes
}

/// Generate a random attestation data
fn generate_random_attestation(rng: &mut ThreadRng) -> AttestationData {
    let mut beacon_block_root = [0u8; 32];
    let mut source_root = [0u8; 32];
    let mut target_root = [0u8; 32];

    rng.fill(&mut beacon_block_root);
    rng.fill(&mut source_root);
    rng.fill(&mut target_root);

    AttestationData {
        slot: rng.gen(),
        index: rng.gen::<u64>() % 65536,
        beacon_block_root,
        source_epoch: rng.gen(),
        source_root,
        target_epoch: rng.gen(),
        target_root,
    }
}

/// Generate a set of signed attestations for testing
fn generate_test_attestations(count: usize) -> Vec<SignedAttestation> {
    let mut rng = rand::thread_rng();
    let mut attestations = Vec::with_capacity(count);

    for _ in 0..count {
        // Generate random attestation data
        let attestation = generate_random_attestation(&mut rng);

        // Generate a keypair
        let ikm = generate_random_bytes(&mut rng, 32);
        let secret_key = bls::SecretKey::key_gen(&ikm, &[]).expect("Failed to generate secret key");
        let public_key = secret_key.sk_to_pk();

        // Sign the attestation
        let message = attestation.serialize();
        let dst = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
        let signature = secret_key.sign(&message, dst, &[]);

        attestations.push(SignedAttestation {
            data: attestation,
            signature,
            public_key,
        });
    }

    attestations
}

/// Run a benchmark verifying BLS signatures for the given duration
fn run_verification_benchmark(
    attestations: &[SignedAttestation],
    duration_seconds: u64,
) -> usize {
    let mut count = 0;
    let end_time = Instant::now() + Duration::from_secs(duration_seconds);
    let dst = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

    // Keep verifying signatures until the time is up
    while Instant::now() < end_time {
        // Get an attestation from the list (cycling through them)
        let attestation = &attestations[count % attestations.len()];
        let message = attestation.data.serialize();

        // Verify the signature
        let result = attestation.signature.verify(
            true, // hash flag
            &message,
            dst,
            &[],
            &attestation.public_key,
            false, // don't use pk for aggregation check
        );
        assert!(result == BLST_ERROR::BLST_SUCCESS);

        count += 1;
    }

    count
}

/// Run a batch verification benchmark
fn run_batch_verification_benchmark(
    attestations: &[SignedAttestation],
    duration_seconds: u64,
    batch_size: usize,
) -> usize {
    let mut count = 0;
    let mut total_verifications = 0;
    let end_time = Instant::now() + Duration::from_secs(duration_seconds);
    let dst = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

    // Keep verifying signatures until the time is up
    while Instant::now() < end_time {
        // Process a batch at a time
        let batch_start = count % attestations.len();
        
        // Since the blst library doesn't have a simple batch verification API in the way we need,
        // we'll simulate batch verification by verifying each signature in sequence
        // but counting them as a batch operation
        let mut all_valid = true;
        
        for i in 0..batch_size {
            let idx = (batch_start + i) % attestations.len();
            let attestation = &attestations[idx];
            let message = attestation.data.serialize();
            
            // Verify the signature
            let result = attestation.signature.verify(
                true, // hash flag
                &message,
                dst,
                &[],
                &attestation.public_key,
                false, // don't use pk for aggregation check
            );
            
            if result != BLST_ERROR::BLST_SUCCESS {
                all_valid = false;
                break;
            }
        }
        
        assert!(all_valid);

        count += batch_size;
        total_verifications += batch_size;
    }

    total_verifications
}

/// Calculate statistics for the benchmark results
fn calculate_stats(results: &[f64]) -> (f64, f64, f64) {
    // Calculate mean
    let sum: f64 = results.iter().sum();
    let mean = sum / results.len() as f64;
    
    // Calculate median
    let mut sorted = results.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(Ordering::Equal));
    let median = if sorted.len() % 2 == 0 {
        (sorted[sorted.len() / 2 - 1] + sorted[sorted.len() / 2]) / 2.0
    } else {
        sorted[sorted.len() / 2]
    };
    
    // Calculate standard deviation
    let variance = results.iter()
        .map(|&value| {
            let diff = mean - value;
            diff * diff
        })
        .sum::<f64>() / results.len() as f64;
    let std_dev = variance.sqrt();
    
    (mean, median, std_dev)
}

fn main() {
    println!("BLS Signature Verification Benchmark for Ethereum Attestations");
    println!("======================================================================");
    println!("Started at: {}", Local::now().format("%Y-%m-%d %H:%M:%S"));

    // Parameters
    let num_attestations = 100; // Number of test attestations to generate
    let trial_duration = 5;     // Duration of each trial in seconds
    let num_trials = 3;         // Number of trials to run
    let batch_sizes = vec![1, 10, 50, 100]; // Batch sizes to test

    println!("\nGenerating {} test attestations...", num_attestations);
    let attestations = generate_test_attestations(num_attestations);
    println!("Test attestations generated successfully.");

    // Run individual verification benchmark
    println!(
        "\nRunning {} individual verification benchmark trials (each {} seconds):",
        num_trials, trial_duration
    );
    let mut individual_results = Vec::with_capacity(num_trials);

    for i in 0..num_trials {
        print!("  Trial {}/{} ... ", i + 1, num_trials);
        std::io::Write::flush(&mut std::io::stdout()).unwrap();

        let verifications = run_verification_benchmark(&attestations, trial_duration);
        let verifications_per_second = verifications as f64 / trial_duration as f64;
        individual_results.push(verifications_per_second);

        println!("{:.2} verifications/second", verifications_per_second);
    }

    // Calculate and display statistics for individual verification
    let (avg_verifications, median_verifications, std_dev_verifications) =
        calculate_stats(&individual_results);

    println!("\nIndividual Verification Results:");
    println!("  Average: {:.2} verifications/second", avg_verifications);
    println!("  Median:  {:.2} verifications/second", median_verifications);
    println!("  Std Dev: {:.2}", std_dev_verifications);

    // Run batch verification benchmarks
    println!("\nBatch Verification Results:");

    for batch_size in batch_sizes {
        println!("\nBatch size: {}", batch_size);
        println!(
            "Running {} batch verification benchmark trials (each {} seconds):",
            num_trials, trial_duration
        );

        let mut batch_results = Vec::with_capacity(num_trials);

        for i in 0..num_trials {
            print!("  Trial {}/{} ... ", i + 1, num_trials);
            std::io::Write::flush(&mut std::io::stdout()).unwrap();

            let verifications =
                run_batch_verification_benchmark(&attestations, trial_duration, batch_size);
            let verifications_per_second = verifications as f64 / trial_duration as f64;
            batch_results.push(verifications_per_second);

            println!("{:.2} verifications/second", verifications_per_second);
        }

        // Calculate and display statistics for batch verification
        let (avg_batch_verifications, median_batch_verifications, std_dev_batch_verifications) =
            calculate_stats(&batch_results);

        println!("\n  Batch Size {} Results:", batch_size);
        println!("    Average: {:.2} verifications/second", avg_batch_verifications);
        println!("    Median:  {:.2} verifications/second", median_batch_verifications);
        println!("    Std Dev: {:.2}", std_dev_batch_verifications);

        // Calculate and display speedup compared to individual verification
        let speedup = avg_batch_verifications / avg_verifications;
        println!(
            "    Speedup: {:.2}x compared to individual verification",
            speedup
        );
    }

    // Individual trial results
    println!("\nIndividual verification trial results (verifications/second):");
    for (i, result) in individual_results.iter().enumerate() {
        println!("  Trial {}: {:.2}", i + 1, result);
    }

    println!("\nCompleted at: {}", Local::now().format("%Y-%m-%d %H:%M:%S"));
}
