package main

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math"
	"sort"
	"time"

	"github.com/herumi/bls-eth-go-binary/bls"
)

// AttestationData represents a simplified Ethereum attestation
type AttestationData struct {
	Slot           uint64
	Index          uint64
	BeaconBlockRoot [32]byte
	SourceEpoch    uint64
	SourceRoot     [32]byte
	TargetEpoch    uint64
	TargetRoot     [32]byte
}

// Serialize converts the attestation data to bytes for signing
func (a *AttestationData) Serialize() []byte {
	buf := make([]byte, 0, 128)

	slotBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(slotBytes, a.Slot)
	buf = append(buf, slotBytes...)

	indexBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(indexBytes, a.Index)
	buf = append(buf, indexBytes...)

	buf = append(buf, a.BeaconBlockRoot[:]...)

	sourceEpochBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(sourceEpochBytes, a.SourceEpoch)
	buf = append(buf, sourceEpochBytes...)

	buf = append(buf, a.SourceRoot[:]...)

	targetEpochBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(targetEpochBytes, a.TargetEpoch)
	buf = append(buf, targetEpochBytes...)

	buf = append(buf, a.TargetRoot[:]...)

	return buf
}

// SignedAttestation represents an attestation with its signature and public key
type SignedAttestation struct {
	Data      AttestationData
	Signature bls.Sign
	PublicKey bls.PublicKey
}

// generateRandomBytes creates random bytes of specified length
func generateRandomBytes(length int) []byte {
	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	if err != nil {
		panic(err)
	}
	return bytes
}

// generateRandomAttestation creates a random attestation data
func generateRandomAttestation() AttestationData {
	var blockRoot, sourceRoot, targetRoot [32]byte
	copy(blockRoot[:], generateRandomBytes(32))
	copy(sourceRoot[:], generateRandomBytes(32))
	copy(targetRoot[:], generateRandomBytes(32))

	return AttestationData{
		Slot:           binary.LittleEndian.Uint64(generateRandomBytes(8)),
		Index:          binary.LittleEndian.Uint64(generateRandomBytes(8)) % 65536,
		BeaconBlockRoot: blockRoot,
		SourceEpoch:    binary.LittleEndian.Uint64(generateRandomBytes(8)),
		SourceRoot:     sourceRoot,
		TargetEpoch:    binary.LittleEndian.Uint64(generateRandomBytes(8)),
		TargetRoot:     targetRoot,
	}
}

// generateTestAttestations creates a set of signed attestations for testing
func generateTestAttestations(count int) []SignedAttestation {
	attestations := make([]SignedAttestation, count)

	for i := 0; i < count; i++ {
		// Generate random attestation data
		attestation := generateRandomAttestation()

		// Generate a keypair
		var secretKey bls.SecretKey
		secretKey.SetByCSPRNG()
		publicKey := secretKey.GetPublicKey()

		// Sign the attestation
		message := attestation.Serialize()
		signature := secretKey.Sign(string(message))

		attestations[i] = SignedAttestation{
			Data:      attestation,
			Signature: *signature,
			PublicKey: *publicKey,
		}
	}

	return attestations
}

// runVerificationBenchmark measures how many verifications can be done in the given duration
func runVerificationBenchmark(attestations []SignedAttestation, durationSeconds int) int {
	count := 0
	endTime := time.Now().Add(time.Duration(durationSeconds) * time.Second)

	// Keep verifying signatures until the time is up
	for time.Now().Before(endTime) {
		// Get an attestation from the list (cycling through them)
		attestation := attestations[count%len(attestations)]
		message := attestation.Data.Serialize()

		// Verify the signature
		if !attestation.Signature.Verify(&attestation.PublicKey, string(message)) {
			panic("Signature verification failed")
		}

		count++
	}

	return count
}

// runBatchVerificationBenchmark measures how many batch verifications can be done
// Since the library doesn't have a built-in batch verification, we'll verify each signature
// but time how long it takes to verify a batch of signatures
func runBatchVerificationBenchmark(attestations []SignedAttestation, durationSeconds int, batchSize int) int {
	count := 0
	totalVerifications := 0
	endTime := time.Now().Add(time.Duration(durationSeconds) * time.Second)

	// Keep verifying signatures until the time is up
	for time.Now().Before(endTime) {
		// Process a batch at a time
		batchStart := count % len(attestations)
		allValid := true

		// Verify each signature in the batch
		for i := 0; i < batchSize; i++ {
			idx := (batchStart + i) % len(attestations)
			attestation := attestations[idx]
			message := attestation.Data.Serialize()

			// Verify the signature
			if !attestation.Signature.Verify(&attestation.PublicKey, string(message)) {
				allValid = false
				break
			}
		}

		if !allValid {
			panic("Batch signature verification failed")
		}

		count += batchSize
		totalVerifications += batchSize
	}

	return totalVerifications
}

// calculateStats computes statistics for the benchmark results
func calculateStats(results []float64) (float64, float64, float64) {
	// Calculate mean
	sum := 0.0
	for _, r := range results {
		sum += r
	}
	mean := sum / float64(len(results))

	// Calculate median
	sortedResults := make([]float64, len(results))
	copy(sortedResults, results)
	sort.Float64s(sortedResults)
	
	var median float64
	if len(sortedResults)%2 == 0 {
		median = (sortedResults[len(sortedResults)/2-1] + sortedResults[len(sortedResults)/2]) / 2
	} else {
		median = sortedResults[len(sortedResults)/2]
	}

	// Calculate standard deviation
	sumSquaredDiff := 0.0
	for _, r := range results {
		diff := r - mean
		sumSquaredDiff += diff * diff
	}
	stdDev := math.Sqrt(sumSquaredDiff / float64(len(results)))

	return mean, median, stdDev
}

func main() {
	// Initialize the BLS library
	err := bls.Init(bls.BLS12_381)
	if err != nil {
		panic(err)
	}
	bls.SetETHmode(bls.EthModeDraft07)

	fmt.Println("BLS Signature Verification Benchmark for Ethereum Attestations")
	fmt.Println("======================================================================")

	// Parameters
	numAttestations := 100 // Number of test attestations to generate
	trialDuration := 5     // Duration of each trial in seconds
	numTrials := 3         // Number of trials to run
	batchSizes := []int{1, 10, 50, 100} // Batch sizes to test

	fmt.Printf("Generating %d test attestations...\n", numAttestations)
	attestations := generateTestAttestations(numAttestations)
	fmt.Println("Test attestations generated successfully.")

	// Run individual verification benchmark
	fmt.Printf("\nRunning %d individual verification benchmark trials (each %d seconds):\n", numTrials, trialDuration)
	individualResults := make([]float64, numTrials)

	for i := 0; i < numTrials; i++ {
		fmt.Printf("  Trial %d/%d... ", i+1, numTrials)
		verifications := runVerificationBenchmark(attestations, trialDuration)
		verificationsPerSecond := float64(verifications) / float64(trialDuration)
		individualResults[i] = verificationsPerSecond
		fmt.Printf("%.2f verifications/second\n", verificationsPerSecond)
	}

	// Calculate and display statistics for individual verification
	avgVerifications, medianVerifications, stdDevVerifications := calculateStats(individualResults)

	fmt.Println("\nIndividual Verification Results:")
	fmt.Printf("  Average: %.2f verifications/second\n", avgVerifications)
	fmt.Printf("  Median:  %.2f verifications/second\n", medianVerifications)
	fmt.Printf("  Std Dev: %.2f\n", stdDevVerifications)

	// Run batch verification benchmarks
	fmt.Println("\nBatch Verification Results:")
	
	for _, batchSize := range batchSizes {
		fmt.Printf("\nBatch size: %d\n", batchSize)
		fmt.Printf("Running %d batch verification benchmark trials (each %d seconds):\n", numTrials, trialDuration)
		
		batchResults := make([]float64, numTrials)
		
		for i := 0; i < numTrials; i++ {
			fmt.Printf("  Trial %d/%d... ", i+1, numTrials)
			verifications := runBatchVerificationBenchmark(attestations, trialDuration, batchSize)
			verificationsPerSecond := float64(verifications) / float64(trialDuration)
			batchResults[i] = verificationsPerSecond
			fmt.Printf("%.2f verifications/second\n", verificationsPerSecond)
		}
		
		// Calculate and display statistics for batch verification
		avgBatchVerifications, medianBatchVerifications, stdDevBatchVerifications := calculateStats(batchResults)
		
		fmt.Printf("\n  Batch Size %d Results:\n", batchSize)
		fmt.Printf("    Average: %.2f verifications/second\n", avgBatchVerifications)
		fmt.Printf("    Median:  %.2f verifications/second\n", medianBatchVerifications)
		fmt.Printf("    Std Dev: %.2f\n", stdDevBatchVerifications)
		
		// Calculate and display speedup compared to individual verification
		speedup := avgBatchVerifications / avgVerifications
		fmt.Printf("    Speedup: %.2fx compared to individual verification\n", speedup)
	}

	// Individual trial results
	fmt.Println("\nIndividual verification trial results (verifications/second):")
	for i, result := range individualResults {
		fmt.Printf("  Trial %d: %.2f\n", i+1, result)
	}
}
