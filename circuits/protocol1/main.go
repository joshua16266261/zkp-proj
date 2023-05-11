package protocol1

import (
	"bytes"
	"fmt"
	"math"

	"github.com/consensys/gnark-crypto/accumulator/merkletree"
	"github.com/consensys/gnark-crypto/ecc"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/accumulator/merkle"
	"github.com/consensys/gnark/std/hash/mimc"
)

const wildcard = "*"

type Circuit struct {
	MerkleProof  merkle.MerkleProof  `gnark:",public"`
	ProofIndex   frontend.Variable   `gnark:",public"`
	ClientString []frontend.Variable `gnark:",public"`
	RawPattern   []frontend.Variable
	// Offset       frontend.Variable
}

func (circuit *Circuit) Define(api frontend.API) error {
	hFunc, _ := mimc.NewMiMC(api)

	// Verify MerkleProof
	circuit.MerkleProof.VerifyProof(api, &hFunc, circuit.ProofIndex)

	// Verify that RawPattern hashes to the opened pattern
	hFunc.Reset()
	hFunc.Write(circuit.RawPattern...)
	api.AssertIsEqual(circuit.MerkleProof.Path[0], hFunc.Sum())

	// Wildcard
	hFunc.Reset()
	var wildcardFieldElement fr.Element
	wildcardFieldElement.SetBytes([]byte(wildcard))

	// Verify that at Offset, RawPattern matches the ClientString
	// offsetBigInt, _ := api.Compiler().ConstantValue(circuit.Offset) // FIXME: At compilation time, this doesn't work and just returns nil
	// // api.AssertIsEqual(success, 1)
	// offset := offsetBigInt.Int64()
	offsetBigInt, _ := api.Compiler().ConstantValue(0) // FIXME: At compilation time, this doesn't work and just returns nil
	// api.AssertIsEqual(success, 1)
	offset := offsetBigInt.Int64()
	for i := int64(0); i < int64(len(circuit.RawPattern)); i++ {
		isWildcard := api.IsZero(api.Sub(wildcardFieldElement, circuit.RawPattern[i+offset]))
		isSame := api.IsZero(api.Sub(circuit.ClientString[i+offset], circuit.RawPattern[i+offset]))
		isMatch := api.Or(isWildcard, isSame)

		api.AssertIsEqual(isMatch, 1)
	}

	return nil
}

// func getHash(pattern string) ([]byte, error) {
// 	// GetHash hashes a string pattern into a single field element

// 	// This line taken from https://github.com/ConsenSys/gnark-crypto/blob/master/ecc/bn254/fr/mimc/mimc.go
// 	elems, err := fr.Hash([]byte(pattern), []byte("string:"), 1)
// 	if err != nil {
// 		return nil, err
// 	}

// 	result := elems[0].Bytes()
// 	return result[:], nil
// }

// func charToFieldElement(char string) (frontend.Variable, error) {
// 	b, err := getHash(char)
// 	if err != nil {
// 		return nil, err
// 	}

// 	var elem fr.Element
// 	return elem.SetBytes(b), nil
// }

// func stringToFieldElement(s string) (frontend.Variable, error) {
// 	hFunc := bn254.NewMiMC()
// 	for _, char := range s {
// 		elem, err := charToFieldElement(string(char))
// 		if err != nil {
// 			return nil, err
// 		}
// 		hFunc.Write()
// 	}

// }

// func fieldElementsToString(pattern []frontend.Variable) string {

// }

// func getFieldElements(pattern string) [][]byte {
// 	// GetFieldElements converts each character of a string pattern into a field element
// 	hFunc := bn254.NewMiMC()
// 	var fieldElems [][]byte
// 	for _, char := range pattern {
// 		hFunc.Reset()
// 		fieldElems = append(fieldElems, hFunc.Sum([]byte(string(char))))
// 	}
// 	return fieldElems
// }

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
	var patternsFieldElements [][][]byte
	for _, pattern := range stringPatterns {
		hashedPattern, err := getHash(pattern)
		if err != nil {
			fmt.Println("Error hashing pattern:", err)
			return
		}
		hashedPatterns = append(hashedPatterns, hashedPattern)

		patternsFieldElements = append(patternsFieldElements, getFieldElements(pattern))
	}

	// Define client string
	clientString := "abcdefghijkl"
	clientStringFieldElements := getFieldElements(clientString)

	// Build merkle proof
	field := ecc.BN254.ScalarField()
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
	depth := int(math.Ceil(math.Log2(float64(len(hashedPatterns)))))

	var circuit Circuit
	circuit.MerkleProof.Path = make([]frontend.Variable, depth+1)
	circuit.ClientString = make([]frontend.Variable, len(clientString))
	circuit.RawPattern = make([]frontend.Variable, len(stringPatterns[proofIndex]))

	r1cs, err := frontend.Compile(field, r1cs.NewBuilder, &circuit)
	if err != nil {
		fmt.Printf("Compile failed : %v\n", err)
		return
	}

	pk, vk, err := groth16.Setup(r1cs)
	if err != nil {
		fmt.Printf("Setup failed\n")
		return
	}

	var merkleProof merkle.MerkleProof
	merkleProof.RootHash = merkleRoot

	merkleProof.Path = make([]frontend.Variable, depth+1)
	for i := 0; i < depth+1; i++ {
		merkleProof.Path[i] = proofPath[i]
	}

	// Full witness
	assignment := &Circuit{
		MerkleProof: merkleProof,
		ProofIndex:  proofIndex,
		// circuit.Offset = 0
	}

	assignment.ClientString = make([]frontend.Variable, len(clientString))
	for i := 0; i < len(clientString); i++ {
		assignment.ClientString[i] = clientStringFieldElements[i]
	}

	assignment.RawPattern = make([]frontend.Variable, len(stringPatterns[proofIndex]))
	for i := 0; i < len(stringPatterns[proofIndex]); i++ {
		assignment.RawPattern[i] = patternsFieldElements[proofIndex][i]
	}

	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		fmt.Println("Witness creation failed:", err)
	}
	proof, err := groth16.Prove(r1cs, pk, witness)
	if err != nil {
		fmt.Printf("Prove failed: %v\n", err)
		return
	}

	// Public witness and verification
	publicWitness, err := witness.Public()
	if err != nil {
		fmt.Println("Public witness creation failed:", err)
	}
	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		fmt.Printf("verification failed: %v\n", err)
		return
	}
	fmt.Printf("verification succeded\n")

}

func Main() {
	// FIXME: This is pretty jank
	main()
}
