package main

import (
	"bytes"
	"fmt"
	"math"

	"github.com/consensys/gnark-crypto/accumulator/merkletree"
	"github.com/consensys/gnark-crypto/ecc"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/accumulator/merkle"
	"github.com/consensys/gnark/std/hash/mimc"
)

type Circuit struct {
	MerkleProof  merkle.MerkleProof  `gnark:",public"`
	ProofIndex   frontend.Variable   `gnark:",public"`
	ClientString []frontend.Variable `gnark:",public"`
	RawPattern   []frontend.Variable
	Offset       frontend.Variable
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

	for i := 0; i < len(circuit.RawPattern); i++ {
		// Check if the element in the pattern is the wildcard
		isWildcard := api.IsZero(api.Sub(wildcardFieldElement, circuit.RawPattern[i]))

		// Check if the elements in the pattern and client string are the same
		idx := api.Add(i, circuit.Offset)
		var clientStringElem frontend.Variable
		clientStringElem = 0
		for j := i; j < len(circuit.ClientString); j++ {
			jIsIdx := api.IsZero(api.Cmp(j, idx))
			clientStringElem = api.Select(jIsIdx, circuit.ClientString[j], clientStringElem)
		}

		isSame := api.IsZero(api.Sub(clientStringElem, circuit.RawPattern[i]))
		isMatch := api.Or(isWildcard, isSame)

		api.AssertIsEqual(isMatch, 1)
	}

	return nil
}

func Protocol1(stringPatterns []string, clientString string, proofIndex uint64, offset int) {
	// Convert patterns to field element vectors and hashes
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

	// Convert clientString to field element vector
	clientStringFieldElements := getFieldElements(clientString)

	// Build merkle proof
	field := ecc.BN254.ScalarField()
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
		Offset:      offset,
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

	// Prove
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
	fmt.Println("Verification succeeded")
}
