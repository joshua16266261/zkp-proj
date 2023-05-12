package main

import (
	"bytes"
	"fmt"
	"reflect"
	"time"

	"github.com/consensys/gnark-crypto/accumulator/merkletree"
	"github.com/consensys/gnark-crypto/hash"
)

func Protocol0(stringPatterns []string, clientString string, proofIndex uint64) {
	// Define patterns
	var hashedPatterns [][]byte
	for _, pattern := range stringPatterns {
		hashedPattern, err := getHash(pattern)
		if err != nil {
			fmt.Println("Error hashing pattern:", err)
			return
		}
		hashedPatterns = append(hashedPatterns, hashedPattern)
	}

	// Build merkle proof
	start := time.Now()
	var buf bytes.Buffer
	for _, pattern := range hashedPatterns {
		buf.Write(pattern)
	}

	hGo := hash.MIMC_BN254.New()
	segmentSize := 32
	merkleRoot, proofPath, _, err := merkletree.BuildReaderProof(bytes.NewReader(buf.Bytes()), hGo, segmentSize, proofIndex)
	// The actual value of the leaf is proofPath[0]
	if err != nil {
		fmt.Println(err)
		return
	}
	duration := time.Since(start)
	fmt.Println("Prover time:", duration)

	start = time.Now()
	isValidProof := merkletree.VerifyProof(hGo, merkleRoot, proofPath, proofIndex, uint64(len(stringPatterns)))
	if !isValidProof {
		fmt.Println("failed to verify proof")
		return
	}

	// Define client string
	hashedClientString, err := getHash(clientString)
	if err != nil {
		fmt.Println("Error hashing clientString:", err)
		return
	}

	patternEqualsString := reflect.DeepEqual(hashedClientString, proofPath[0])
	if !patternEqualsString {
		fmt.Println("client string and pattern do not match")
		return
	}
	duration = time.Since(start)
	fmt.Println("Verifier time:", duration)

	fmt.Println("Verification succeeded")
}
