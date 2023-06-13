package hotstuff_pseudocode

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	mrand "math/rand"
	"strconv"
	"time"
)

// TxnMsg Just creating TxnMsg to avoid errors
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

func VerifySignature(hash [32]byte, publicKey PublicKey, signature []byte) bool {
	return true
}

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
