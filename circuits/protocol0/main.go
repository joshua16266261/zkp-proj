package protocol0

import (
	"bytes"
	"fmt"
	"reflect"
	"time"

	"github.com/consensys/gnark-crypto/accumulator/merkletree"
	bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark-crypto/hash"
)

func getFieldElements(pattern string) [][]byte {
	// GetFieldElements converts each character of a string pattern into a field element
	var fieldElems [][]byte

	blockSize := bn254.BlockSize

	for _, char := range pattern {
		b := make([]byte, blockSize)
		b[blockSize-1] = byte(char)
		fieldElems = append(fieldElems, b)
	}
	return fieldElems
}

func getHash(pattern string) ([]byte, error) {
	// GetHash hashes a string pattern into a single field element

	converted := getFieldElements(pattern)
	var flattened []byte
	for _, elem := range converted {
		flattened = append(flattened, elem...)
	}

	return bn254.Sum(flattened)
}

func main() {
	// Define patterns
	stringPatterns := []string{"abcdefghijkl", "de*"}
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
	proofIndex := uint64(0)
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
	clientString := "abcdefghijkl"
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

func Main() {
	// FIXME: This is pretty jank
	main()
}
