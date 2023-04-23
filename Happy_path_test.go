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
	genesisBlock := Block{PreviousBlockHash: [32]byte{}, View: 0}
	safeBlocks := NewSafeBlockMap()
	safeBlocks.Put(&genesisBlock)

	// Set up a mock VoteMessage
	vote := &VoteMessage{
		ValidatorPublicKey:            leaderPubKey,
		PartialViewBlockHashSignature: []byte("sig1"),
		BlockHash:                     genesisBlock.Hash(),
		View:                          1,
	}

	// Set up a mock voteseen map with one vote
	voteseen := &map[[32]byte]map[string]VoteMessage{
		Hash(1, genesisBlock.Hash()): {
			string(leaderPubKey): *vote,
		},
	}

	// Call handleVoteMessageFromPeer with the mock arguments
	handleVoteMessageFromPeer(vote, node, safeBlocks, voteseen)

	// Assert that the vote was added to the voteseen map
	if _, ok := (*voteseen)[Hash(1, genesisBlock.Hash())][string(leaderPubKey)]; !ok {
		t.Errorf("Expected vote to be added to voteseen map")
	}

	// Assert that the total vote stake is correctly computed
	expectedVoteStake := 100 // the leader has a stake of 100
	voteStake := ComputeStake((*voteseen)[Hash(1, genesisBlock.Hash())], node.PubKeyToStake)
	if voteStake != expectedVoteStake {
		t.Errorf("Expected vote stake to be %d, but got %d", expectedVoteStake, voteStake)
	}

	// TODO: add more test cases for the remaining scenarios covered by handleVoteMessageFromPeer
}
