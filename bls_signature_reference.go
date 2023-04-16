//go:build relic

package main

import (
	"context"
	"github.com/deso-protocol/core/lib"
	flowCrypto "github.com/onflow/flow-go/crypto"
	"github.com/onflow/flow-go/crypto/hash"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/semaphore"
	"math/rand"
	"runtime"
	"sync"
	"testing"
	"time"
)

const randomSeed = 15
const totalPublicKeys = 100
const totalMessages = 10
const benchmarkPublicKeys = 1000

func TestBLS(t *testing.T) {
	lib.Mode = lib.EnableTimer
	require := require.New(t)
	rand.Seed(randomSeed)

	// Generate random (private, public) key pairs with a total number of totalPublicKeys.
	var allPublicKeys []flowCrypto.PublicKey
	var allPrivateKeys []flowCrypto.PrivateKey
	for ii := 0; ii < totalPublicKeys; ii++ {
		randBytes := lib.RandomBytes(64)
		privateKey, err := flowCrypto.GeneratePrivateKey(flowCrypto.BLSBLS12381, randBytes)
		require.NoError(err)

		allPrivateKeys = append(allPrivateKeys, privateKey)
		allPublicKeys = append(allPublicKeys, privateKey.PublicKey())

		// # IMPORTANT SECURITY NOTE #
		// Whenever validator registers his public key on the blockchain, he needs to
		// provide what is known as a Proof of Possession (PoP). This prevents a type of
		// exploit known as "Rouge-Key Attack". In this attack, a malicious user could run
		// some function on a validator's registered public key to get another public key,
		// without knowing the corresponding private key, and use it to impersonate or mimic
		// the validator. Preventing this is actually really simple. We just require validators
		// to provide a signature of their public key when registering on the blockchain.
		// That's it, but to sound sophisticated we call it Proof of Possession.
		// https://rist.tech.cornell.edu/papers/pkreg.pdf
		sigPoP, err := flowCrypto.BLSGeneratePOP(privateKey)
		require.NoError(err)
		valid, err := flowCrypto.BLSVerifyPOP(privateKey.PublicKey(), sigPoP)
		require.NoError(err)
		require.Equal(true, valid)
	}

	// Only numberOfSigners = [1, totalPublicKeys/2] out of totalPublicKeys will be
	// used for signature aggregation. The signers will be the first public keys in
	// the allPublicKeys array.
	numberOfSigners := rand.Intn(totalPublicKeys/2) + 1
	randomMessage := lib.RandomBytes(200)

	var signatures []flowCrypto.Signature
	bitList := bitfield.NewBitlist(totalPublicKeys)
	kmac := flowCrypto.NewExpandMsgXOFKMAC128("test tag")
	for ii := 0; ii < numberOfSigners; ii++ {
		iithSignature, err := allPrivateKeys[ii].Sign(randomMessage, kmac)
		require.NoError(err)
		signatures = append(signatures, iithSignature)
		bitList.SetBitAt(uint64(ii), true)
	}

	// Now aggregate all the signatures into a single signature of randomMessage.
	aggregatedSignature, err := flowCrypto.AggregateBLSSignatures(signatures)
	require.NoError(err)

	// Finally, verify that the signature is valid over the set of first numberOfSigners
	// public keys from our list of allPublicKeys.
	valid, err := flowCrypto.VerifyBLSSignatureOneMessage(allPublicKeys[:numberOfSigners], aggregatedSignature,
		randomMessage, kmac)
	require.NoError(err)
	require.Equal(true, valid)
	// Also verify the signature using the bitmask method
	valid, err = _verifySignatureWithBitlist(bitList, allPublicKeys, aggregatedSignature, randomMessage, kmac)
	require.NoError(err)
	require.Equal(true, valid)
	t.Logf("Signature aggregation passed got Valid=(%v)", valid)

	// Sanity-check try a bunch of random bitmasks to make sure that the signature
	// is only valid under the precise bitList we found.
	for ii := 0; ii < 100; ii++ {
		fakeBitList := bitfield.NewBitlist(totalPublicKeys)
		for jj := 0; jj < totalPublicKeys; jj++ {
			if rand.Int()%2 == 1 {
				fakeBitList.SetBitAt(uint64(jj), true)
			}
		}
		fakeValid, err := _verifySignatureWithBitlist(fakeBitList, allPublicKeys, aggregatedSignature,
			randomMessage, kmac)
		require.NoError(err)
		require.Equal(false, fakeValid)
	}
}

func TestBLSMultiSignature(t *testing.T) {
	require := require.New(t)
	rand := rand.New(rand.NewSource(time.Now().UnixNano()))
	kmac := flowCrypto.NewExpandMsgXOFKMAC128("test tag")

	// Only numberOfSigners = [1, totalPublicKeys/2] out of totalPublicKeys will be
	// used for signature aggregation. The signers will be the first public keys in
	// the allPublicKeys array.
	numberOfSigners := rand.Intn(totalPublicKeys/2) + 1
	// Generate totalMessage random byte sequences.
	payloads := make([][]byte, 10)
	for ii := 0; ii < totalMessages; ii++ {
		payloads[ii] = lib.RandomBytes(200)
	}

	// Generate random (private, public) key pairs with a total number of totalPublicKeys.
	var allPublicKeys []flowCrypto.PublicKey
	var allPrivateKeys []flowCrypto.PrivateKey
	var signatures []flowCrypto.Signature
	var inputHashers []hash.Hasher
	var inputPayloads [][]byte

	// Generate all key paris.
	for ii := 0; ii < totalPublicKeys; ii++ {
		randBytes := lib.RandomBytes(64)
		privateKey, err := flowCrypto.GeneratePrivateKey(flowCrypto.BLSBLS12381, randBytes)
		require.NoError(err)

		// Append all the data to our lists.
		allPrivateKeys = append(allPrivateKeys, privateKey)
		allPublicKeys = append(allPublicKeys, privateKey.PublicKey())

	}

	// Create signatures from the first numberOfSigners of the allPublicKeys.
	bitList := bitfield.NewBitlist(totalPublicKeys)
	for ii := 0; ii < numberOfSigners; ii++ {
		// pick a random payload to sign
		payload := payloads[rand.Int()%len(payloads)]
		iithSignature, err := allPrivateKeys[ii].Sign(payload, kmac)
		require.NoError(err)

		inputPayloads = append(inputPayloads, payload)
		inputHashers = append(inputHashers, kmac)
		signatures = append(signatures, iithSignature)
		bitList.SetBitAt(uint64(ii), true)
	}

	// Aggregate all signatures into a single signature and verify that it's a valid multi-signature.
	aggregatedSignature, err := flowCrypto.AggregateBLSSignatures(signatures)
	require.NoError(err)

	valid, err := flowCrypto.VerifyBLSSignatureManyMessages(allPublicKeys[:numberOfSigners], aggregatedSignature, inputPayloads, inputHashers)
	require.NoError(err)
	require.Equal(true, valid)

	// Also verify the signature using the bitmask method
	valid, err = _verifyMultiSignatureWithBitList(bitList, allPublicKeys, aggregatedSignature, inputPayloads, inputHashers)
	require.NoError(err)
	require.Equal(true, valid)

	// Sanity-check try a bunch of different bitmasks to make sure that the signature
	// is only valid under the precise bitList we found.
	for ii := 0; ii < 10; ii++ {
		fakeBitList := bitfield.NewBitlist(totalPublicKeys)
		for jj := 1 + ii; jj < numberOfSigners+1+ii; jj++ {
			fakeBitList.SetBitAt(uint64(jj), true)
		}

		fakeValid, err := _verifyMultiSignatureWithBitList(fakeBitList, allPublicKeys, aggregatedSignature,
			inputPayloads, inputHashers)
		require.NoError(err)
		require.Equal(false, fakeValid)
	}

	// Sanity-check change one of the input messages to make sure that the signature
	// is only valid under the precise set of messages that were used during signing.
	for ii := 0; ii < 10; ii++ {
		randomPayload := rand.Intn(numberOfSigners)
		prevPayload := inputPayloads[randomPayload]
		newPayload := lib.RandomBytes(200)
		inputPayloads[randomPayload] = newPayload

		// Make sure the verification fails now.
		fakeValid, err := _verifyMultiSignatureWithBitList(bitList, allPublicKeys, aggregatedSignature,
			inputPayloads, inputHashers)
		require.NoError(err)
		require.Equal(false, fakeValid)

		// Revert to the previous message list and check that signature verification passes.
		inputPayloads[randomPayload] = prevPayload
		valid, err = _verifyMultiSignatureWithBitList(bitList, allPublicKeys, aggregatedSignature, inputPayloads, inputHashers)
		require.NoError(err)
		require.Equal(true, valid)
	}
}

func TestBenchmarkBLS(t *testing.T) {
	require := require.New(t)

	// Generate benchmarkPublicKeys that we'll use for our test.
	// Sign the random message using a worker pool to speed things up.
	var allPublicKeys []flowCrypto.PublicKey
	var allSignatures []flowCrypto.Signature
	var appendMutex sync.Mutex
	kmac := flowCrypto.NewExpandMsgXOFKMAC128("test tag")
	randomMessage := lib.RandomBytes(200)
	maxWorkers := int64(runtime.GOMAXPROCS(0))
	sem := semaphore.NewWeighted(maxWorkers)
	ctx := context.Background()

	startTime := time.Now()
	for ii := 0; ii < benchmarkPublicKeys; ii++ {
		randBytes := lib.RandomBytes(64)
		privateKey, err := flowCrypto.GeneratePrivateKey(flowCrypto.BLSBLS12381, randBytes)
		require.NoError(err)

		require.NoError(sem.Acquire(ctx, 1))
		go func(key flowCrypto.PrivateKey) {
			defer sem.Release(1)
			signature, err := key.Sign(randomMessage, kmac)
			require.NoError(err)
			appendMutex.Lock()
			allPublicKeys = append(allPublicKeys, privateKey.PublicKey())
			allSignatures = append(allSignatures, signature)
			appendMutex.Unlock()
		}(privateKey)
	}
	require.NoError(sem.Acquire(ctx, maxWorkers))
	sem.Release(maxWorkers)
	totalTime := time.Since(startTime).Seconds()
	t.Logf("Making (%v) signatures in an pool of (%v) workers takes (%v) seconds",
		benchmarkPublicKeys, maxWorkers, totalTime)

	// Now let's test how long it would take the leader to aggregate all these signatures into
	// a single signature.
	// BENCHMARK RESULT: ~0.5 seconds to aggregate 10,000 signatures.
	startTime = time.Now()
	aggregatedSignature, err := flowCrypto.AggregateBLSSignatures(allSignatures)
	require.NoError(err)
	totalTime = time.Since(startTime).Seconds()
	t.Logf("Aggregating (%v) signatures takes (%v) seconds",
		benchmarkPublicKeys, totalTime)

	// Finally, let's test how long it takes to verify the aggregate signature for a validator.
	// BENCHMARK RESULT: ~0.03 seconds to verify an aggregate signature of 10,000 users.
	startTime = time.Now()
	valid, err := flowCrypto.VerifyBLSSignatureOneMessage(allPublicKeys, aggregatedSignature,
		randomMessage, kmac)
	require.NoError(err)
	require.Equal(true, valid)
	totalTime = time.Since(startTime).Seconds()
	t.Logf("Verifying an aggregated signature of (%v) users takes (%v) seconds",
		benchmarkPublicKeys, totalTime)
}

// _verifySignatureWithBitlist checks whether the provided signature is valid given a bitmask of all public keys.
func _verifySignatureWithBitlist(bitlist bitfield.Bitlist, allPublicKeys []flowCrypto.PublicKey,
	aggregatedSignature flowCrypto.Signature, message []byte, kmac hash.Hasher) (_valid bool, _err error) {

	var signerPublicKeys []flowCrypto.PublicKey
	for ii := uint64(0); ii < bitlist.Len(); ii++ {
		if bitlist.BitAt(ii) {
			signerPublicKeys = append(signerPublicKeys, allPublicKeys[ii])
		}
	}

	return flowCrypto.VerifyBLSSignatureOneMessage(signerPublicKeys, aggregatedSignature, message, kmac)
}

// _verifyMultiSignatureWithBitList checks whether the provided multi-signature is valid given a bitmask of all public keys.
func _verifyMultiSignatureWithBitList(bitlist bitfield.Bitlist, allPublicKeys []flowCrypto.PublicKey,
	aggregatedSignature flowCrypto.Signature, messages [][]byte, kmac []hash.Hasher) (_valid bool, _err error) {

	var signerPublicKeys []flowCrypto.PublicKey
	for ii := uint64(0); ii < bitlist.Len(); ii++ {
		if bitlist.BitAt(ii) {
			signerPublicKeys = append(signerPublicKeys, allPublicKeys[ii])
		}
	}

	return flowCrypto.VerifyBLSSignatureManyMessages(signerPublicKeys, aggregatedSignature, messages, kmac)
}
