package hotstuff_pseudocode

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	mrand "math/rand"
	"reflect"
	"sort"
	"strconv"
	"time"
)

// TxnMsg represents a blockchain transaction. We make it simple by just having a from, to, and amount fields.
type TxnMsg struct {
	From   string
	To     string
	Amount int
}

func GenerateTxns(n int) []TxnMsg {
	mrand.Seed(time.Now().UnixNano())

	var txns []TxnMsg
	for i := 0; i < n; i++ {
		txns = append(txns, TxnMsg{
			From:   strconv.Itoa(mrand.Intn(1000)),
			To:     strconv.Itoa(mrand.Intn(1000)),
			Amount: mrand.Intn(100),
		})
	}
	return txns
}

// Sign signs the payload with the private key. For the purpose of this pseudocode, we skip this step.
func Sign(payload [32]byte, privKey PrivateKey) ([]byte, error) {
	return []byte{}, nil
}

// VerifySignature verifies the signature of a message. For the purpose of this pseudocode,
// we skip this step and just return true.
func VerifySignature(hash [32]byte, publicKey PublicKey, signature []byte) bool {
	return true
}

// VerifyBLSCombinedSignature verifies the BLS combined/aggregate signature given a list of public keys and a hash. For the
// purpose of this pseudocode, we skip this step and just return true. More details can be found in the
// bls_signature_reference.go file.
func VerifyBLSCombinedSignature(hash [32]byte, publicKey []string, signature []byte) bool {
	return true
}

// VerifyBLSMultiSignature validates the BLS multi-signature given a list of public keys and payloads. Note that BLS
// multi-signatures can be a result of aggregating BLS signatures on different payloads. The general rule is that
// given a list of [(BLSSignature, pubKey, payload), ...] triples, we can aggregate them into a single BLSMultiSignature
// that can be verified given a list of [(pubKey, payload), ...] pairs. For the purpose of this pseudocode, we skip this
// step and just return true. More details can be found in the bls_signature_reference.go file.
func VerifyBLSMultiSignature(hashes [][32]byte, publicKeys []string, signature []byte) bool {
	return true
}

// verifySignaturesAndTxns verifies block's sanity based on consensus rules. This includes things like validating
// that transactions are properly formatted and signed. For the purpose of this pseudocode, we skip this step and
// just return true.
func verifySignaturesAndTxns(block Block) bool {
	return true
}

// Hash combines the view number with data into a single hash.
func Hash(viewNumber uint64, data interface{}) [32]byte {
	var dataBytes []byte
	switch data.(type) {
	case []TxnMsg:
		txnBytes, err := json.Marshal(data)
		if err != nil {
			panic(err)
		}
		dataBytes = txnBytes
	case uint64:
		viewBytes := []byte(fmt.Sprintf("%d", data))
		dataBytes = viewBytes
	case [32]byte:
		for _, b := range data.([32]byte) {
			dataBytes = append(dataBytes, b)
		}
	case nil:

	default:
		panic("invalid data type")
	}
	viewBytes := []byte(fmt.Sprintf("%d", viewNumber))
	viewHash := sha256.Sum256(viewBytes)
	var combinedHash [32]byte

	if dataBytes != nil {
		combinedHash = sha256.Sum256(append(dataBytes, viewHash[:]...))
	} else {
		combinedHash = sha256.Sum256(viewHash[:])
	}
	return combinedHash
}

// computeLeader returns the public key of the leader for a particular view.
func computeLeader(view uint64, pubKeyToStake map[string]uint64) (string, error) {

	comulativeStakeSlice, orderedpubkeys, _ := calculateCumulativeStakesSlice(pubKeyToStake)

	// Initialize the random number generator with the provided seed
	r := mrand.New(mrand.NewSource(int64(view)))
	totalStake := uint64(0)
	for _, pubkey := range orderedpubkeys {
		totalStake = totalStake + pubKeyToStake[pubkey]
	}

	// Generate a random number within the range of 0 to totalStake
	randomNumber := r.Uint64() % (totalStake + 1)

	for idx, cumulativestake := range comulativeStakeSlice {

		if randomNumber <= cumulativestake {
			return orderedpubkeys[idx], nil
		}

	}
	return "", fmt.Errorf("no leader found")

}

// calculateCumulativeStakesSlice sorts the map of (publicKey => stake) KV pairs into an ordered list based on public keys.
// The resulting ordered list is kept by validators and will be referenced by the BLSMultiSignature. Essentially, the i-th
// bit in the ValidatorIDBitmap will reference the i-th pair in the ordered list. Also, the ordered list will be used
// to determine the leader for a given view.
func calculateCumulativeStakesSlice(pubKeyToStake map[string]uint64) (
	_cumulativeStake []uint64, _publicKeys []string, _err error) {

	cumulativeStakesSlice := make([]uint64, 0, len(pubKeyToStake))
	var cumulativeStake uint64

	// Sort the public keys lexicographically
	var pubKeys []string
	for pubKey := range pubKeyToStake {
		pubKeys = append(pubKeys, pubKey)
	}
	sort.Strings(pubKeys)

	for _, pubKey := range pubKeys {
		stake := pubKeyToStake[pubKey]
		if stake == 0 {
			return nil, nil, fmt.Errorf("stake for pubkey '%s' cannot be zero", pubKey)
		}

		cumulativeStake += stake
		cumulativeStakesSlice = append(cumulativeStakesSlice, cumulativeStake)
	}

	if cumulativeStake == 0 {
		return nil, nil, fmt.Errorf("total stake cannot be zero")
	}

	return cumulativeStakesSlice, pubKeys, nil
}

// Validates supermajority has voted in QC. For the purpose of this pseudocode,
// we skip this step and just return true.
func ValidateSuperMajority_QC(signature BLSMultiSignature) bool {
	return true
}

// ValidateSuperMajority_AggQC Validate super majority has sent their timeout msgs. For the purpose of this pseudocode,
// we skip this step and just return true.
func ValidateSuperMajority_AggQC(signature BLSMultiSignature) bool {
	return true
}

// ComputeStake calculates the total stake of the validators included in a VoteMessage or TimeoutMessage.
func ComputeStake(messages interface{}, pubKeyToStake map[string]uint64) uint64 {
	totalStake := uint64(0)
	switch m := messages.(type) {
	case map[string]VoteMessage:
		for _, vote := range m {
			if stake, exists := pubKeyToStake[string(vote.ValidatorPublicKey)]; exists {
				totalStake += stake
			}
		}
	case map[string]TimeoutMessage:
		for _, timeout := range m {
			if stake, exists := pubKeyToStake[string(timeout.ValidatorPublicKey)]; exists {
				totalStake += stake

			}
		}
	}
	return totalStake
}

// GetTotalStake calculates the total stake of all validators.
func GetTotalStake(pubKeyToStake map[string]uint64) uint64 {
	totalStake := uint64(0)
	for _, stake := range pubKeyToStake {
		totalStake += stake
	}
	return totalStake
}

// This function is used to extract indices encoded in the signer bitmap.
func getOnBitIndices(bitmap []byte) []int {
	indices := make([]int, 0)
	for i := 0; i < len(bitmap)*8; i++ {
		if getBitAtIndex(bitmap, i) {
			indices = append(indices, i)
		}
	}
	return indices
}

func getBitAtIndex(bitmap []byte, i int) bool {
	byteIndex := i / 8
	bitIndex := uint(i % 8)
	return bitmap[byteIndex]&(1<<bitIndex) != 0
}

// This function is used to extract public keys encoded in the signer bitmap, given a list of all public keys.
func getBitmapPublicKeys(bitmap []byte, publicKeys []string) []string {
	indices := getOnBitIndices(bitmap)
	bitmapPublicKeys := make([]string, 0)
	for _, index := range indices {
		bitmapPublicKeys = append(bitmapPublicKeys, publicKeys[index])
	}
	return bitmapPublicKeys
}

// Contains returns true if the given key is in the map, and false otherwise.
func Contains(m interface{}, key interface{}) (bool, error) {
	v := reflect.ValueOf(m)
	if v.Kind() != reflect.Map {
		return false, errors.New("m is not a map")
	}
	if v.IsNil() {
		return false, errors.New("m is nil")
	}
	k := reflect.ValueOf(key)
	if k.Type() != v.Type().Key() {
		return false, errors.New("key type does not match map key type")
	}
	elemType := v.Type().Elem()
	if elemType.Kind() == reflect.Ptr {
		elemType = elemType.Elem()
	}
	zero := reflect.Zero(elemType)

	if !v.MapIndex(k).IsValid() {
		return false, nil
	}
	return !reflect.DeepEqual(v.MapIndex(k).Interface(), zero.Interface()), nil
}

// verifyValidatorPublicKey verifies that the given validator public key is in the list of public keys.
func verifyValidatorPublicKey(validatorPublicKey PublicKey, publicKeys []PublicKey) bool {
	for _, publicKey := range publicKeys {
		if bytes.Equal(publicKey[:], validatorPublicKey[:]) {
			return true
		}
	}
	return false
}

// Send represents a network primitive responsible for sending a vote/timeout to the next leader. We leave it
// unimplemented for the sake of simplicity.
func Send(msg interface{}, nextleader PublicKey) {
	switch msg.(type) {
	case VoteMessage:
		// send vote message
	case TimeoutMessage:
		// send timeout message
	default:
		// handle unknown message type
	}
}

// Broadcast represents a network primitive responsible for broadcasting a block to all validators. We leave it
// unimplemented for the sake of simplicity.
func Broadcast(block Block) {}
