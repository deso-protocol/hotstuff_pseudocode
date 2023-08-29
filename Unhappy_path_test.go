package hotstuff_pseudocode

import (
	"fmt"
	"testing"
	"time"
)

// Tests if timer get doubled after each timeout
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

func TestAppendTimeoutMessage(t *testing.T) {
	txns := GenerateTxns(3)

	leaderPubKey := []byte("leader pub key")
	leaderPrivKey := []byte("leader priv key")
	genesisBlock := Block{Txns: txns, View: 0}
	node := &Node{
		CurView: 0,
		HighestQC: &QuorumCertificate{
			View:                           0,
			BlockHash:                      Hash(genesisBlock.View, genesisBlock.Txns),
			CombinedViewBlockHashSignature: BLSMultiSignature{CombinedSignature: []byte("a"), ValidatorIDBitmap: []byte("a")},
		},
		PubKeys:         []PublicKey{{}},
		PrivKey:         (*PrivateKey)(&leaderPrivKey),
		Last_voted_view: 0,
		PubKey:          (*PublicKey)(&leaderPubKey),
		PubKeyToStake: map[string]uint64{
			string(leaderPubKey): 100,
			"pubKey2":            200,
			"pubKey3":            300,
			"pubKey4":            400,
		},
	}

	for key := range node.PubKeyToStake {
		node.PubKeys = append(node.PubKeys, []byte(key))
	}
	timeoutsSeen := TimeoutsSeenMap{
		Timeout: make(map[[32]byte]map[string]TimeoutMessage),
	}

	timer := NewTimer(2 * time.Second)

	timeoutMsg := timer.CreateTimeout_msg(node)

	fmt.Println("timeout msg is ", timeoutMsg)
	handleTimeoutMessageFromPeer(*timeoutMsg, node, timeoutsSeen)

	// Assert that the timeout message was appended to timeoutsSeen
	innerMap, ok := timeoutsSeen.Timeout[Hash(timeoutMsg.View, nil)]
	if !ok {
		t.Errorf("Inner map not found for hash %s", Hash(timeoutMsg.View, nil))
	}
	_, ok = innerMap[string(timeoutMsg.ValidatorPublicKey)]
	if !ok {
		t.Errorf("Timeout message not found for validator %s", string(timeoutMsg.ValidatorPublicKey))
	}
}

func TestGetHighestViewHighQC(t *testing.T) {
	// Create a map of timeout messages with different high QCs
	timeoutSeen := map[string]TimeoutMessage{
		"timeout1": {
			HighQC: QuorumCertificate{
				View: 1,
			},
		},
		"timeout2": {
			HighQC: QuorumCertificate{
				View: 2,
			},
		},
		"timeout3": {
			HighQC: QuorumCertificate{
				View: 3,
			},
		},
	}

	// Call the function under test
	highestHighQC := GetHighestViewHighQC(timeoutSeen)

	// Check the result
	expectedView := uint64(3)
	//expectedBlockHash := []byte("block3")
	if highestHighQC.View != expectedView {
		t.Errorf("Expected highest view to be %d, but got %d", expectedView, highestHighQC.View)
	}

}

func TestGetTimeouthighQcViews(t *testing.T) {
	// Create a map of timeout messages with different high QCs
	timeoutSeen := map[string]TimeoutMessage{
		"timeout1": {
			HighQC: QuorumCertificate{
				View: 1,
			},
		},
		"timeout2": {
			HighQC: QuorumCertificate{
				View: 2,
			},
		},
		"timeout3": {
			HighQC: QuorumCertificate{
				View: 3,
			},
		},
	}

	// Call the function under test
	views := GetTimeouthighQcViews(timeoutSeen)

	// Check the result
	expectedViews := []uint64{1, 2, 3}
	if len(views) != len(expectedViews) {
		t.Errorf("Expected %d views, but got %d views", len(expectedViews), len(views))
	}

	for _, view := range expectedViews {
		found := false
		for _, v := range views {
			if v == view {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected view %d not found in the result", view)
		}
	}
}

func TestGetTimeouthighQcViews_EmptyMap(t *testing.T) {
	// Create an empty map of timeout messages
	timeoutSeen := map[string]TimeoutMessage{}

	// Call the function under test
	views := GetTimeouthighQcViews(timeoutSeen)

	// Check the result
	if len(views) != 0 {
		t.Errorf("Expected 0 views, but got %d views", len(views))
	}
}

func TestHandleTimeoutMessagesForBlockCreation(t *testing.T) {
	txns := GenerateTxns(3)

	leaderPubKey := []byte("pubKey1")
	leaderPrivKey := []byte("leader priv key")
	genesisBlock := Block{Txns: txns, View: 0}
	node := &Node{
		CurView: 0,
		HighestQC: &QuorumCertificate{
			View:                           0,
			BlockHash:                      Hash(genesisBlock.View, genesisBlock.Txns),
			CombinedViewBlockHashSignature: BLSMultiSignature{CombinedSignature: []byte("a"), ValidatorIDBitmap: []byte("a")},
		},
		PubKeys:         []PublicKey{},
		PrivKey:         (*PrivateKey)(&leaderPrivKey),
		Last_voted_view: 0,
		PubKey:          (*PublicKey)(&leaderPubKey),
		PubKeyToStake: map[string]uint64{
			"pubKey1": 100,
			"pubKey2": 200,
			"pubKey3": 300,
			"pubKey4": 400,
		},
	}
	timer := NewTimer(1 * time.Second)

	// Assign the timer to node.Timer
	node.Timer = timer
	//fmt.Println("node.Timer is", *node.Timer)

	// Start the timer
	node.Timer.Start(node)
	for key := range node.PubKeyToStake {
		node.PubKeys = append(node.PubKeys, []byte(key))
	}
	fmt.Println("Pubkeys are ", node.PubKeys)
	// Create a map to store the timeout messages
	timeoutsSeen := TimeoutsSeenMap{
		Timeout: make(map[[32]byte]map[string]TimeoutMessage),
	}

	// Create timeout messages from different public keys
	timeoutMsg1 := TimeoutMessage{
		ValidatorPublicKey:          node.PubKeys[0],
		View:                        node.CurView + 1,
		HighQC:                      *node.HighestQC,
		PartialTimeoutViewSignature: []byte("signature1"),
	}
	//	AppendTimeoutMessage(&timeoutsSeen, timeoutMsg1)

	timeoutMsg2 := TimeoutMessage{
		ValidatorPublicKey:          node.PubKeys[1],
		View:                        node.CurView + 1,
		HighQC:                      *node.HighestQC,
		PartialTimeoutViewSignature: []byte("signature2"),
	}
	//AppendTimeoutMessage(&timeoutsSeen, timeoutMsg2)

	timeoutMsg3 := TimeoutMessage{
		ValidatorPublicKey:          node.PubKeys[2],
		View:                        node.CurView + 1,
		HighQC:                      *node.HighestQC,
		PartialTimeoutViewSignature: []byte("signature3"),
	}

	timeoutMsg4 := TimeoutMessage{
		ValidatorPublicKey:          node.PubKeys[3],
		View:                        node.CurView + 1,
		HighQC:                      *node.HighestQC,
		PartialTimeoutViewSignature: []byte("signature4"),
	}
	//AppendTimeoutMessage(&timeoutsSeen, timeoutMsg3)

	// Save the initial timeoutStake
	//	// Call handleTimeoutMessageFromPeer to create a block with an aggregated QC
	handleTimeoutMessageFromPeer(timeoutMsg1, node, timeoutsSeen)
	handleTimeoutMessageFromPeer(timeoutMsg2, node, timeoutsSeen)
	handleTimeoutMessageFromPeer(timeoutMsg3, node, timeoutsSeen)
	handleTimeoutMessageFromPeer(timeoutMsg4, node, timeoutsSeen)

	//fmt.Println("TImeoutSeen map is after adding 3 timeout msgs  is ", timeoutsSeen.Timeout)
	// Verify if the timeoutStake has increased
	updatedTimeoutStake := ComputeStake(timeoutsSeen.Timeout[Hash(timeoutMsg1.View, nil)], node.PubKeyToStake)

	if updatedTimeoutStake != 1000 {
		t.Errorf("InvalTimeout stake")
	}

	// Call handleBlockFromPeer to handle the created block
	leader, _ := computeLeader(node.CurView+1, node.PubKeyToStake)

	block := Block{
		ProposerPublicKey: PublicKey(leader),
		Txns:              GenerateTxns(10),
		View:              node.CurView + 1,
		QC:                *node.HighestQC,
		AggregateQC: AggregateQC{
			View:                               node.CurView,
			ValidatorTimeoutHighQC:             *node.HighestQC,
			ValidatorTimeoutHighQCViews:        []uint64{node.CurView},
			ValidatorCombinedTimeoutSignatures: BLSMultiSignature{[]byte("a"), []byte("a")},
		},
	}
	block.ProposerSignature, _ = Sign(Hash(block.View, block.Txns), *node.PrivKey)

	safeblocks := NewSafeBlockMap()
	committedblocks := &CommittedBlockMap{}
	safeblocks.Put(&genesisBlock)

	handleBlockFromPeer(&block, node, safeblocks, committedblocks)

	// Check if the block is in the safe blocks
	if ok, _ := Contains(safeblocks.Blocks, Hash(block.View, block.Txns)); !ok {
		t.Errorf("Block not found in safe blocks")
	}
}
func TestTimerDuration(t *testing.T) {
	// Initialize the required variables and structs
	leaderPubKey := []byte("leader pub key")
	leaderPrivKey := []byte("leader priv key")
	txns := GenerateTxns(3)

	genesisBlock := Block{Txns: txns, View: 0}

	node := &Node{
		CurView:         0,
		Last_voted_view: 0,
		PubKey:          (*PublicKey)(&leaderPubKey),
		PrivKey:         (*PrivateKey)(&leaderPrivKey),
		PubKeyToStake:   make(map[string]uint64),
		HighestQC: &QuorumCertificate{
			View:                           0,
			BlockHash:                      Hash(genesisBlock.View, genesisBlock.Txns),
			CombinedViewBlockHashSignature: BLSMultiSignature{CombinedSignature: []byte("a"), ValidatorIDBitmap: []byte("a")},
		},
	}

	// Create a new timer with a base duration of 1 second
	timer := NewTimer(1 * time.Second)

	// Assign the timer to node.Timer
	node.Timer = timer
	//fmt.Println("node.Timer is", *node.Timer)

	// Start the timer
	node.Timer.Start(node)

	// Wait for the timer to expire (1 second)
	time.Sleep(1200 * time.Millisecond)

	// Check if the duration has been doubled
	expectedDuration := 2 * time.Second
	actualDuration := node.Timer.getDuration()
	if actualDuration != expectedDuration {
		t.Errorf("Expected duration to be %v, but got %v", expectedDuration, actualDuration)
	}

	// Reset the timer
	node.Timer.Reset()
	// Wait for the timer to expire (1 second)
	//time.Sleep(1 * time.Second)

	// Check if the duration is still the base duration
	expectedDuration = 1 * time.Second
	actualDuration = node.Timer.getDuration()
	if actualDuration != expectedDuration {
		t.Errorf("Expected duration to be %v, but got %v", expectedDuration, actualDuration)
	}

	// Stop the timer
	node.Timer.Stop()
}
