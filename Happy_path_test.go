package hotstuff_pseudocode

import (
	"fmt"
	"testing"
)

func NewSafeBlockMap() *SafeBlockMap {
	return &SafeBlockMap{
		Blocks: make(map[[32]byte]*Block),
	}
}

func NewCommittedBlock() *CommittedBlockMap {
	return &CommittedBlockMap{
		Block: make(map[[32]byte]*Block),
	}
}
func TestHandleVoteMessageFromPeer(t *testing.T) {
	// Set up a mock Node with a leader pubkey and privkey
	leaderPubKey := []byte("leader pub key")
	leaderPrivKey := []byte("leader priv key")
	node := &Node{
		CurView: 1,
		PubKey:  (*PublicKey)(&leaderPubKey),
		PrivKey: (*PrivateKey)(&leaderPrivKey),
		//AmIaLeader:= true,
		PubKeyToStake: map[string]uint64{
			string(leaderPubKey): 100,
			"validator1":         50,
			"validator2":         50,
		},
	}

	// Set up a mock SafeBlockMap with a single block
	genesisBlock := Block{View: 0, Txns: GenerateTxns(3)}
	safeBlocks := NewSafeBlockMap()
	safeBlocks.Put(&genesisBlock)

	// Set up a mock VoteMessage
	vote := &VoteMessage{
		ValidatorPublicKey:            leaderPubKey,
		PartialViewBlockHashSignature: []byte("sig1"),
		BlockHash:                     Hash(genesisBlock.View, genesisBlock.Txns),
		View:                          1,
	}

	// Set up a mock voteseen map with one vote
	voteseen := &map[[32]byte]map[string]VoteMessage{
		Hash(1, genesisBlock.Txns): {
			string(leaderPubKey): *vote,
		},
	}

	// Call handleVoteMessageFromPeer
	handleVoteMessageFromPeer(vote, node, safeBlocks, voteseen)

	// Assert that the vote was added to the voteseen map
	if _, ok := (*voteseen)[Hash(1, genesisBlock.Txns)][string(leaderPubKey)]; !ok {
		t.Errorf("Expected vote to be added to voteseen map")
	}

	// Assert that the total vote stake is correctly computed
	expectedVoteStake := uint64(100) // the leader has a stake of 100
	voteStake := ComputeStake((*voteseen)[Hash(1, genesisBlock.Txns)], node.PubKeyToStake)
	if voteStake != expectedVoteStake {
		t.Errorf("Expected vote stake to be %d, but got %d", expectedVoteStake, voteStake)
	}

}

// Handling block proposed by a randomly chosen leader
func TestHandleBlockFromPeer(t *testing.T) {
	txns := GenerateTxns(3)

	// Create a genesis block
	genesisBlock := Block{Txns: txns, View: 0}

	// Create a safe block map and add the genesis block to it
	safeBlocks := NewSafeBlockMap()
	safeBlocks.Put(&genesisBlock)

	// Create a committed block map and add the genesis block to it
	committedBlocks := NewCommittedBlock()
	committedBlocks.Put(&genesisBlock)

	// Create a node with the genesis block as its highest QC
	leaderPubKey := []byte("leader pub key")
	leaderPrivKey := []byte("leader priv key")

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

	// Create three blocks with the appropriate QC
	txns = GenerateTxns(3)
	output, _ := computeLeader(1, node.PubKeyToStake)
	block1 := Block{Txns: txns, View: 1, ProposerPublicKey: PublicKey(output)}
	fmt.Println("Computed leader for block in the test ", string(block1.ProposerPublicKey))

	qc1 := QuorumCertificate{
		View:                           0,
		BlockHash:                      Hash(genesisBlock.View, genesisBlock.Txns),
		CombinedViewBlockHashSignature: BLSMultiSignature{CombinedSignature: []byte("a"), ValidatorIDBitmap: []byte("a")},
	}
	block1.SetQC(&qc1)
	txns = GenerateTxns(3)
	leader, _ := computeLeader(2, node.PubKeyToStake)
	block2 := Block{Txns: txns, View: 2, ProposerPublicKey: PublicKey(leader)}
	fmt.Println("Computed leader for block in the test", string(block2.ProposerPublicKey))
	qc2 := QuorumCertificate{
		View:                           1,
		BlockHash:                      Hash(block1.View, block1.Txns),
		CombinedViewBlockHashSignature: BLSMultiSignature{CombinedSignature: []byte("a"), ValidatorIDBitmap: []byte("a")},
	}
	block2.SetQC(&qc2)
	txns = GenerateTxns(3)
	//	fmt.Println("block1 propose is", string(PublicKey(computeLeader(1, node.PubKeyToStake))))

	//	fmt.Println("block2 propose is", string(PublicKey(computeLeader(2, node.PubKeyToStake))))

	//	fmt.Println("block3 propose is", string(PublicKey(computeLeader(3, node.PubKeyToStake))))
	leader, _ = computeLeader(3, node.PubKeyToStake)

	block3 := Block{Txns: txns, View: 3, ProposerPublicKey: PublicKey(leader)}
	fmt.Println("Computed leader for block in the test", string(block3.ProposerPublicKey))

	qc3 := QuorumCertificate{
		View:                           2,
		BlockHash:                      Hash(block2.View, block2.Txns),
		CombinedViewBlockHashSignature: BLSMultiSignature{CombinedSignature: []byte("a"), ValidatorIDBitmap: []byte("a")},
	}
	block3.SetQC(&qc3)

	// Handle the three blocks from peers
	fmt.Println("PubkeyToStake map inside test is ", node.PubKeyToStake)
	fmt.Println("handling block 1 ", block1)
	fmt.Println("Block1.view inside test is ", block1.View)
	handleBlockFromPeer(&block1, node, safeBlocks, committedBlocks)
	fmt.Println("handling block 2 ", block2)
	fmt.Println("Block1.view inside test is ", block2.View)

	handleBlockFromPeer(&block2, node, safeBlocks, committedBlocks)
	fmt.Println("handling block 3 ", block3)
	fmt.Println("Block1.view inside test is ", block3.View)

	handleBlockFromPeer(&block3, node, safeBlocks, committedBlocks)
	// Verify that block1 is in the committed block map
	//if !committedBlocks.Contains(block1.Hash()) {
	if ok, err := Contains(committedBlocks.Block, Hash(1, block1.Txns)); err != nil || !ok {
		t.Errorf("Block 1 not found in committed block map")
	}

	// Verify that block2 and block3 are in the safe block map
	if ok, err := Contains(safeBlocks.Blocks, Hash(2, block2.Txns)); err != nil || !ok {
		t.Errorf("Block 2 not found in safe block map")
	}

	if ok, err := Contains(safeBlocks.Blocks, Hash(3, block3.Txns)); err != nil || !ok {
		t.Errorf("Block 3 not found in safe block map")
	}

	if ok, _ := Contains(committedBlocks.Block, Hash(3, block3.Txns)); ok {
		t.Errorf("Block 3 is found in Committed block map. It shouldn't have been saved")
	}

	////Verify node state
	if node.CurView != 3 {
		t.Errorf("view has not been correctly incremented.")

	}

	if node.Last_voted_view != 3 {
		t.Errorf("last_voted_view has not been correctly incremented.")

	}

}

/*func TestChooseLeader(t *testing.T) {
	// Define the stake weights
	pubKeyToStake := map[string]uint64{
		"pubKey1": 100,
		"pubKey2": 200,
		"pubKey3": 300,
		"pubKey4": 400,
	}

	// Define the expected stake distribution (within a certain range)
	expectedRange := 0.1
	minExpectedCount := int(float64(10) * (0.4 - expectedRange))
	maxExpectedCount := int(float64(10) * (0.4 + expectedRange))

	// Counters for each leader
	leaderCounts := map[string]int{
		"pubKey1": 0,
		"pubKey2": 0,
		"pubKey3": 0,
		"pubKey4": 0,
	}

	// Repeat the leader computation 1000 times
	for i := 0; i < 10; i++ {
		viewNum := uint64(i) // View number ranges from 0 to 2

		// Compute the leader for the current view
		leader, _ := computeLeader(viewNum, &pubKeyToStake)

		// Increment the counter for the computed leader
		leaderCounts[leader]++
	}

	// Check if the leaders are within the expected stake distribution
	for leader, count := range leaderCounts {
		//expectedCount := pubKeyToStake[leader]
		if count < minExpectedCount || count > maxExpectedCount {
			t.Errorf("Unexpected leader count for %s. Got %d, expected range: [%d, %d]", leader, count, minExpectedCount, maxExpectedCount)
		}
	}
}
*/
