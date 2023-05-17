package hotstuff_pseudocode

import (
	"testing"
	"time"
)

func TestTimer(t *testing.T) {
	// Initialize the required variables and structs
	txns := GenerateTxns(3)

	leaderPubKey := []byte("leader pub key")
	leaderPrivKey := []byte("leader priv key")
	genesisBlock := Block{Txns: txns, View: 0}

	node := &Node{
		Id:      1,
		CurView: 0,
		HighestQC: &QuorumCertificate{
			View:                           0,
			BlockHash:                      Hash(genesisBlock.View, genesisBlock.Txns),
			CombinedViewBlockHashSignature: BLSMultiSignature{CombinedSignature: []byte("a"), ValidatorIDBitmap: []byte("a")},
		},
		PubKey:              (*PublicKey)(&leaderPubKey),
		PrivKey:             (*PrivateKey)(&leaderPrivKey),
		PubKeys:             make([]PublicKey, 2),
		LatestCommittedView: 0,
		Last_voted_view:     0,
		PubKeyToStake:       make(map[string]uint64),
	}

	// Create a new timer with a base duration of 1 second
	timer := NewTimer(1 * time.Second)

	// Start the timer
	timer.Start(node)

	// Wait for the timer to expire (adjust the wait time as needed)
	time.Sleep(2 * time.Second)

	// Stop the timer
	timer.Stop()

	// Check the value of node's view
	if node.CurView != 1 {
		t.Errorf("Expected node's view to be 1, but got %d", node.CurView)
	}
	if node.Last_voted_view != 1 {
		t.Errorf("Expected node's last voted view to be 1, but got %d", node.Last_voted_view)
	}

	// Check if the duration has been doubled
	expectedDuration := 2 * time.Second
	actualDuration := timer.getDuration()
	if actualDuration != expectedDuration {
		t.Errorf("Expected duration to be %v, but got %v", expectedDuration, actualDuration)
	}
}
