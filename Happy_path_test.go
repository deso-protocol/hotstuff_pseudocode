package hotstuff_pseudocode

import (
	"sync"
	"testing"
)

func NewSafeBlockMap() *SafeBlockMap {
	return &SafeBlockMap{
		Blocks: make(map[[32]byte]*Block),
		Mutex:  sync.Mutex{},
	}
}

func NewCommittedBlock() *CommittedBlockMap {
	return &CommittedBlockMap{
		Block: make(map[[32]byte]*Block),
		Mutex: sync.Mutex{},
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
		PubKeyToStake: map[string]int{
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
	expectedVoteStake := 100 // the leader has a stake of 100
	voteStake := ComputeStake((*voteseen)[Hash(1, genesisBlock.Txns)], node.PubKeyToStake)
	if voteStake != expectedVoteStake {
		t.Errorf("Expected vote stake to be %d, but got %d", expectedVoteStake, voteStake)
	}

}

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
	//leaderPrivKey := []byte("leader priv key")
	node := Node{
		CurView: 0,
		HighestQC: &QuorumCertificate{
			View:                           0,
			BlockHash:                      Hash(0, genesisBlock.Txns),
			CombinedViewBlockHashSignature: BLSCombinedSignature{CombinedSignature: []byte("a"), ValidatorIDBitmap: []byte("a")},
		},
		PubKeys:         []PublicKey{{}},
		PrivKey:         &PrivateKey{},
		Last_voted_view: 0,
		PubKey:          (*PublicKey)(&leaderPubKey),
	}

	// Create three blocks with the appropriate QC
	txns = GenerateTxns(3)
	block1 := Block{Txns: txns, View: 1}
	qc1 := QuorumCertificate{
		View:                           0,
		BlockHash:                      Hash(0, genesisBlock.Txns),
		CombinedViewBlockHashSignature: BLSCombinedSignature{CombinedSignature: []byte("a"), ValidatorIDBitmap: []byte("a")},
	}
	block1.SetQC(&qc1)
	txns = GenerateTxns(3)

	block2 := Block{Txns: txns, View: 2}
	qc2 := QuorumCertificate{
		View:                           1,
		BlockHash:                      Hash(1, block1.Txns),
		CombinedViewBlockHashSignature: BLSCombinedSignature{CombinedSignature: []byte("a"), ValidatorIDBitmap: []byte("a")},
	}
	block2.SetQC(&qc2)
	txns = GenerateTxns(3)
	block3 := Block{Txns: txns, View: 3}
	qc3 := QuorumCertificate{
		View:                           2,
		BlockHash:                      Hash(2, block2.Txns),
		CombinedViewBlockHashSignature: BLSCombinedSignature{CombinedSignature: []byte("a"), ValidatorIDBitmap: []byte("a")},
	}
	block3.SetQC(&qc3)

	// Handle the three blocks from peers
	handleBlockFromPeer(&block1, &node, safeBlocks, committedBlocks)
	handleBlockFromPeer(&block2, &node, safeBlocks, committedBlocks)
	handleBlockFromPeer(&block3, &node, safeBlocks, committedBlocks)

	// Verify that block1 is in the committed block map
	//if !committedBlocks.Contains(block1.Hash()) {
	if ok, err := Contains(committedBlocks.Block, Hash(1, block1.Txns), &committedBlocks.Mutex); err != nil || !ok {
		t.Errorf("Block 1 not found in committed block map")
	}

	// Verify that block2 and block3 are in the safe block map
	if ok, err := Contains(safeBlocks.Blocks, Hash(2, block2.Txns), &safeBlocks.Mutex); err != nil || !ok {
		t.Errorf("Block 2 not found in safe block map")
	}

	if ok, err := Contains(safeBlocks.Blocks, Hash(3, block3.Txns), &safeBlocks.Mutex); err != nil || !ok {
		t.Errorf("Block 3 not found in safe block map")
	}

	if ok, err := Contains(committedBlocks.Block, Hash(3, block3.Txns), &committedBlocks.Mutex); err == nil || ok {
		t.Errorf("Block 3 is found in Committed block map. It shouldn't have been saved")
	}
}
