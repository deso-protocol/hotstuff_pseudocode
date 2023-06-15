package hotstuff_pseudocode

import (
	"bytes"

	"fmt"
	"math"
	"time"
)

// This corresponds to the Algorithm 3 in the Fast-HotStuff
// paper https://arxiv.org/pdf/2010.11454.pdf

type BLSPartialSignature []byte

type BLSMultiSignature struct {
	CombinedSignature []byte
	ValidatorIDBitmap []byte
}

type Node struct {
	Id                  int
	CurView             uint64
	HighestQC           *QuorumCertificate
	PubKey              *PublicKey
	PrivKey             *PrivateKey
	ValidatorPubKeys    []PublicKey
	LatestCommittedView uint64
	Last_voted_view     uint64
	PubKeyToStake       map[string]uint64
	Timer               *Timer
	votesSeen           VotesSeenMap
	timeoutsSeen        TimeoutsSeenMap
	safeBlocks          SafeBlockMap
	committedBlocks     CommittedBlockMap
}

// Set of SafeBlocks and CommittedBlocks
type SafeBlockMap struct {
	Blocks map[[32]byte]*Block
}
type CommittedBlockMap struct {
	Block map[[32]byte]*Block
}

func (sbm *SafeBlockMap) Put(block *Block) {
	sbm.Blocks[Hash(block.View, block.Txns)] = block
}

func (cbm *CommittedBlockMap) Put(block *Block) {
	cbm.Block[Hash(block.View, block.Txns)] = block
}

// VotesSeenMap is a map of the hash(block.view, block.hash) to map string (vote.voter)
type VotesSeenMap struct {
	Votes map[[32]byte]map[string]VoteMessage
}

// TimeoutsSeenMap type is similar to votesSeen. It stores the timeout messages seen by the leader in the current view.
// It is map of the hash(timeout.view) to map string (timeoutMessage.ValidatorPublickey)
type TimeoutsSeenMap struct {
	Timeouts map[[32]byte]map[string]TimeoutMessage
}

// For the purposes of this code, we will assume that PublicKey and PrivateKey can
// be used to sign and verify BLS signatures. Note that BLS signatures require a little
// more setup in order to be use-able, but that setup is not needed for the purposes of
// this pseudocode.
type PublicKey []byte
type PrivateKey []byte

func (pk PublicKey) Equals(other PublicKey) bool {
	return bytes.Equal(pk, other)
}

func (pk PublicKey) ToString() string {
	return string(pk)
}

// When a validator receives a block that they believe to be valid, they send
// a VoteMessage back to the leader with a signature that the leader can then
// package into a QuorumCertificate for that block.
type VoteMessage struct {
	// The public key of the validator who's sending this message.
	ValidatorPublicKey PublicKey

	// The view of the block that this validator is voting for.
	// Note that the view isn't explicitly needed here, as the block will contain
	// the view regardless, but we include it for convenience and ease of
	// debugging.
	View uint64

	// The hash of the block that this validator is voting for.
	BlockHash [32]byte

	// This is a signature of the (View, BlockHash) pair referenced above. It indicates
	// that this validator believes this block to be valid at this particular view.
	PartialViewBlockHashSignature BLSPartialSignature
}

// A QuorumCertificate is a collection of signatures from 2/3rds of the validators
// on the network, weighted by Stake. The signatures are associated with a particular
// block and a particular view in which that block was proposed.
type QuorumCertificate struct {

	// The hash of the block that this QuorumCertificate authorizes.
	BlockHash [32]byte

	// The view corresponding to the block that this QuorumCertificate authorizes.
	View uint64

	// This signature is a BLSMultiSignature that is the result of combining
	// all of the PartialViewBlockHashSignatures from the VoteMessages that were
	// aggregated by a leader. Note that the signature includes the ValidatorIDBitmap
	// which the recipient can use to verify the signature and to verify the amount
	// of stake that the signers collectively own. While we refer to this signature
	// as a multi-signature for simplicity, all validators signed the same message,
	// being the View.
	CombinedViewBlockHashSignature BLSMultiSignature
}

// The TimeoutMessage is sent from a validator to the next leader when that
// validator wants to timeout on a particular view. It contains the highest QC
// that the validator is aware of. This QC then allows the leader to link back to
// the most recent block that 2/3rds of validators are aware of when constructing
// the next block.
//
// When a leader receives a TimeoutMessage for a particular view from 2/3rds of the
// validators, weighted by Stake, the leader can construct an AggregateQC, which they
// can then include in a proposed block.
type TimeoutMessage struct {

	// The public key of the validator who's sending this message.
	ValidatorPublicKey PublicKey

	// The view that the validator wants to skip over (because they haven't received a
	// valid block for it and they timed out).
	View uint64

	// The QuorumCertificate with the highest view that the validator is aware
	// of. This QC allows the leader to link back to the most recent block that
	// 2/3rds of validators are aware of when constructing the next block.
	HighQC QuorumCertificate

	// A signature of (TimeoutView, HighQC.View) that indicates this validator
	// wants to timeout. Notice that we include the HighQC.View in the signature
	// payload rather than signing the full serialized HighQC itself. This allows the leader
	// to better aggregate validator signatures without compromising the integrity
	// of the protocol.
	PartialTimeoutViewSignature BLSPartialSignature
}

// AggregateQC is an aggregation of timeout messages from 2/3rds of all validators,
// weighted by stake, that indicates that these validators want to time out a
// particular view.
//
// During timeouts, the timeout block leader is supposed to extend the chain from
// the highest QC that he received from the validators who timed out. And the leader
// creates the AggregateQC to prove that he has selected the highest QC for his block.
// The AggregateQC contains a list of high QC views that each validator has signed and
// sent to the leader along with a single multi-signature that serves as a cryptographic
// proof of what each validator has said.
//
// As we're using a BLS multi-signature scheme, we are forced to include the same
// number of views as there were signers, even if multiple validators signed the
// same view.
type AggregateQC struct {

	// The view that this AggregateQC corresponds to. This is the view that the
	// validators decided to timeout on.
	View uint64

	// The highest QC extracted from all the TimeoutMessages that the leader received.
	ValidatorTimeoutHighQC QuorumCertificate

	// Here we include a list of the HighQC.View values we got from each of the
	// validators in the ValidatorTimeoutHighQCViews field. In addition, for each
	// unique HighQC.View value we received, we combine all the PartialTimeoutViewSignatures
	// for that HighQC.View into a single BLSMultiSignature.
	//https://crypto.stanford.edu/~dabo/pubs/papers/BLSmultisig.html
	ValidatorTimeoutHighQCViews        []uint64
	ValidatorCombinedTimeoutSignatures BLSMultiSignature
}

func (aqc AggregateQC) isEmpty() bool {
	if aqc.View == 0 && aqc.ValidatorCombinedTimeoutSignatures.CombinedSignature == nil {
		return true

	}
	return false
}

type Block struct {

	// The public key of the leader who is proposing this block.
	ProposerPublicKey PublicKey

	// List of transactions contained in this block. This data is what all
	// the validators are attempting to agree on in the consensus.
	Txns []TxnMsg

	// View in which this block is proposed.
	View uint64

	// QC contains a list of VoteViewBlockHashSignatures from 2/3rds of the validators
	// weighted by stake.
	QC QuorumCertificate

	// AggregateQC is set to nil whenever a regular block vote takes place.
	// In the case of timeouts, the AggregateQC is set. It serves as proof
	// that 2/3rds of the validators, weighted by stake, timed out.
	AggregateQC AggregateQC

	// The signature of the block made by the leader.
	ProposerSignature BLSPartialSignature
}

func (b *Block) SetQC(qc *QuorumCertificate) {
	b.QC = *qc
}

// The AdvanceView function is used to reset the leader’s vote and timeout maps and
// increment the currentView.
func (node *Node) AdvanceView(block *Block) {
	// Notice that we set the CurView to +1 of the view of the block we just voted on. This allows us to safely forward-skip
	// in case our node is behind. This is safe because we know that a supermajority has voted on this block, and that the
	// block's view is ahead of our current view, which we verify in sanityCheckBlock.
	if block.AggregateQC.isEmpty() {
		node.CurView = block.QC.View + 1
	} else {
		node.CurView = block.AggregateQC.View + 1

	}
	fmt.Println("node.Timer is", *node.Timer)

	node.Timer.Reset()
}

// GetBlockIDForView returns the block ID / hash for a given view.
func (node *Node) GetBlockIDForView(view uint64) ([32]byte, error) {
	for _, block := range node.safeBlocks.Blocks {
		if block.View == view {
			return Hash(block.View, block.Txns), nil
		}
	}
	return [32]byte{}, fmt.Errorf("block not found for view %d", view)
}

// IsLeader returns true if the node is the leader for the given view. For the sake of tests, we return true for every view.
func (node *Node) IsLeader(view uint64) bool {
	pk, err := computeLeader(view, node.PubKeyToStake)
	if err != nil {
		return false
	}
	return pk == node.PubKey.ToString()
}

// commitChainFromGrandParent represents our commit rule. It is called whenever we receive a new block to determine
// if we can commit any blocks that we've previously received. The Fast-HotStuff commit rule finalizes blocks once
// we observe a two-chain involving a direct one-chain. In other words, we must observe a sequence of three blocks:
// 		B1 - B2 - ... - B3
// such that B1 is the parent of B2, and B2 is an ancestor of B3. The ancestor-descendant relationship is established
// whenever a block contains the QC for another block. We say that this block is the descendant of the other block.
// In particular, if the two blocks were proposed with consecutive views, we say these blocks are in a parent-child
// relationship. So, when we observe the aforementioned configuration of B1, B2, and B3, we finalize all ancestors of
// B1 as well as B1. To see why this is safe, one is referred to read the Fast-HotStuff paper.
func (node *Node) commitChainFromGrandParent(block *Block) {
	// In accordance to the above comment, B3 = block, B2 = parent, and B1 = grandParent.
	parent := node.safeBlocks.Blocks[block.QC.BlockHash]
	if parent == nil {
		return
	}

	grandParent := node.safeBlocks.Blocks[parent.QC.BlockHash]
	if grandParent == nil {
		return
	}

	// We verify that B1 is the parent of B2.
	if parent.View != (grandParent.View + 1) {
		return
	}

	// We have successfully observed a committing configuration, we will now commit all ancestors of B1 as well as B1.
	for view := node.LatestCommittedView + 1; view <= grandParent.View; view++ {
		blockHash, err := node.GetBlockIDForView(view)
		if err != nil {
			return
		}

		block, ok := node.safeBlocks.Blocks[blockHash]
		if !ok {
			break
		}

		if _, ok := node.committedBlocks.Block[blockHash]; ok {
			continue
		}

		node.committedBlocks.Block[blockHash] = block
		node.LatestCommittedView = view
	}
}

// sanityCheckBlock is used to verify that the block contains valid information.
func (node *Node) sanityCheckBlock(block Block) bool {
	// We ensure the currently observed block is either for the current view, or for a future view.
	if block.View < node.CurView {
		return false
	}

	// We ensure the node hasn't already voted for this view.
	if block.View <= node.Last_voted_view {
		return false
	}

	// Check that the block's proposer is the expected leader for the current view.
	leader, _ := computeLeader(block.View, node.PubKeyToStake)
	if !block.ProposerPublicKey.Equals(PublicKey(leader)) {
		return false
	}

	// Make sure the leader signed the block.
	if !VerifySignature(Hash(block.View, block.Txns), block.ProposerPublicKey, block.ProposerSignature) {
		return false
	}

	// The block's QC should never be empty.
	if &block.QC == nil {
		return false
	}

	// We make sure the QC contains valid signatures from 2/3rds of validators, weighted by stake. And that the
	// combined signature is valid.
	if !node.validateQuorumCertificate(block.QC) {
		return false
	}

	// verifySignaturesAndTxns checks the transactions contained in the block are valid and have
	// correct signatures. We make sure that the block connects to the rest of the chain.
	if !verifySignaturesAndTxns(block) {
		return false
	}

	return true
}

// validateQuorumCertificate is used to verify that the validators included in the QC collectively own at least 2/3rds
// of the stake. Also make sure there are no repeated public keys. Note that we use the Bitmap contained in the
// combined signature to determine which validators' signatures were used, and what their total stake was.
func (node *Node) validateQuorumCertificate(qc QuorumCertificate) bool {
	if !ValidateSuperMajority_QC(qc.CombinedViewBlockHashSignature) {
		return false
	}

	// Verify the QC combined signature.
	hash := Hash(qc.View, qc.BlockHash)
	_, publicKeys, err := calculateCumulativeStakesSlice(node.PubKeyToStake)
	if err != nil {
		return false
	}
	signerPublicKeys := getBitmapPublicKeys(qc.CombinedViewBlockHashSignature.ValidatorIDBitmap, publicKeys)

	if !VerifyBLSCombinedSignature(hash, signerPublicKeys, qc.CombinedViewBlockHashSignature.CombinedSignature) {
		return false
	}

	return true
}

// validateTimeoutProof is used to verify that the validators included in the QC collectively own at least 2/3rds
// of the stake. Also make sure there are no repeated public keys. Note the bitmap in the signature allows us to
// determine how much stake the validators had.
func (node *Node) validateTimeoutProof(aggregateQC AggregateQC) bool {

	if !ValidateSuperMajority_AggQC(aggregateQC.ValidatorCombinedTimeoutSignatures) {
		return false
	}

	// Extract the highest QC view from the AggregateQC.
	highestQCView := uint64(0)
	for _, view := range aggregateQC.ValidatorTimeoutHighQCViews {
		if view > highestQCView {
			highestQCView = view
		}
	}

	// The highest QC view found in the signatures should match the highest view
	// of the HighestQC included in the AggregateQC.
	if highestQCView != aggregateQC.ValidatorTimeoutHighQC.View {
		return false
	}

	// Verify the HighQC included in the AggregateQC.
	if !node.validateQuorumCertificate(aggregateQC.ValidatorTimeoutHighQC) {
		return false
	}

	// Now we verify the BLS multi-signature.
	hashes := make([][32]byte, len(aggregateQC.ValidatorTimeoutHighQCViews))
	for i, view := range aggregateQC.ValidatorTimeoutHighQCViews {
		hashes[i] = Hash(view, nil)
	}
	_, publicKeys, err := calculateCumulativeStakesSlice(node.PubKeyToStake)
	if err != nil {
		return false
	}
	signerPublicKeys := getBitmapPublicKeys(aggregateQC.ValidatorCombinedTimeoutSignatures.ValidatorIDBitmap, publicKeys)

	if !VerifyBLSMultiSignature(hashes, signerPublicKeys, aggregateQC.ValidatorCombinedTimeoutSignatures.CombinedSignature) {
		return false
	}

	return true
}

// The handleBlockFromPeer is called whenever we receive a block from a peer.
func (node *Node) handleBlockFromPeer(block *Block) {
	// Make sure that the block contains a valid QC, signature, transactions,
	// and that it's for the current view.
	if !node.sanityCheckBlock(*block) {
		return
	}

	// The safeVote variable will tell us if we can vote on this block.
	safeVote := false
	// If the block doesn’t contain an AggregateQC, then that indicates that we
	// did NOT timeout in the previous view, which means we should just check that
	// the QC corresponds to the previous view.
	if block.AggregateQC.isEmpty() {
		// The block is safe to vote on if it is a direct child of the previous
		// block. This means that the parent and child blocks have consecutive
		// views. We use the current block’s QC to find the view of the parent.
		safeVote = block.View == block.QC.View+1
	} else {
		// If we have an AggregateQC set on the block, it means the nodes decided
		// to skip a view by sending TimeoutMessages to the leader, so we process
		// the block accordingly.

		// First we make sure the block contains a valid AggregateQC.
		node.validateTimeoutProof(block.AggregateQC)
		// We find the QC with the highest view among the QCs contained in the
		// AggregateQC.
		highestTimeoutQC := block.AggregateQC.ValidatorTimeoutHighQC
		// If our local highestQC has a smaller view than the highestTimeoutQC,
		// we update our local highestQC.
		if highestTimeoutQC.View > node.HighestQC.View {
			node.HighestQC = &(highestTimeoutQC)
		}
		// We make sure that the block’s QC matches the view of the highest QC that we’re aware of.
		safeVote = block.QC.View == node.HighestQC.View && block.AggregateQC.View+1 == block.View
	}

	// If safeVote is true, we will vote on the block.
	if safeVote {
		// Construct the vote message. The vote will contain the validator's
		// signature on the <view, blockHash> pair.
		payload := Hash(block.View, block.Txns)
		blockHashSignature, _ := Sign(payload, *node.PrivKey)

		voteMsg := VoteMessage{
			ValidatorPublicKey:            *node.PubKey,
			View:                          block.View,
			BlockHash:                     Hash(block.View, block.Txns),
			PartialViewBlockHashSignature: blockHashSignature,
		}
		// Send the vote directly to the next leader.
		leader, _ := computeLeader(node.CurView+1, node.PubKeyToStake)
		Send(voteMsg, PublicKey(leader))
		// We can now proceed to the next view.
		node.AdvanceView(block)
		node.Last_voted_view = uint64(math.Max(float64(node.Last_voted_view), float64(node.CurView)))

		// Add the block to the safeblocks struct.
		node.safeBlocks.Put(block)
	}

	// Our commit rule relies on the fact that blocks were produced without timeouts.
	// Check if the chain looks like this:
	// B1 - B2 - ... - B_current (current block)
	// Where ... represent an arbitrary number of skipped views.

	node.commitChainFromGrandParent(block)
}

// validateVote is used to verify a voteMessage.
func (node *Node) validateVote(vote VoteMessage) bool {
	// Make sure the vote is made on the block in the previous view.
	if vote.View < node.CurView {
		return false
	}

	// Make sure that the validator is registered.
	if !verifyValidatorPublicKey(vote.ValidatorPublicKey, node.ValidatorPubKeys) {
		return false
	}

	// Make sure that the BlockHash in the view matches our local BlockHash history.
	blockHash, err := node.GetBlockIDForView(vote.View)
	if err != nil {

	}
	if blockHash != vote.BlockHash {
		return false
	}

	// Now verify the <view, BlockHash> signature
	payload := Hash(vote.View, vote.BlockHash)
	if !VerifySignature(payload, vote.ValidatorPublicKey, vote.PartialViewBlockHashSignature) {
		return false
	}

	return true
}

// AppendVoteMessage adds vote message to our internal votesSeen data structure.
func (node *Node) AppendVoteMessage(vote VoteMessage) {
	// Check if the outer key exists in the map
	innerMap, ok := node.votesSeen.Votes[Hash(vote.View, vote.BlockHash)]
	if !ok {
		// Initialize the inner map if it doesn't exist
		innerMap = make(map[string]VoteMessage)
		node.votesSeen.Votes[Hash(vote.View, vote.BlockHash)] = innerMap
	}

	// Check if the inner key exists in the inner map
	_, ok = innerMap[string(vote.ValidatorPublicKey)]
	if ok {
		// If the inner key exists, the validator has already voted for the given (view, blockHash) pair
		// and the new vote should be rejected.
		return
	}

	// Add the new vote to the inner map
	innerMap[string(vote.ValidatorPublicKey)] = vote
}

// The handleVoteMessageFromPeer is called whenever we receive a vote from a peer.
func (node *Node) handleVoteMessageFromPeer(vote *VoteMessage) {
	// If we're not the leader, ignore all votes.
	if !node.IsLeader(vote.View + 1) {
		return
	}

	// Make sure that the vote is for the currentView and validate
	// the vote’s signature. We also run a check to make sure we didn’t
	// already receive a timeout or another vote from this peer.
	if !node.validateVote(*vote) {
		return
	}

	// If we get here, it means we are the leader so add the vote to our map of
	// votes seen.
	node.AppendVoteMessage(*vote)

	// Check if we’ve gathered votes from 2/3rds of the validators, weighted by stake.

	messages := node.votesSeen.Votes[Hash(vote.View, vote.BlockHash)]
	voteStake := ComputeStake(messages, node.PubKeyToStake)
	if voteStake < 2*GetTotalStake(node.PubKeyToStake)/3 {
		return
	}

	// At this point, we have collected enough votes to know that we can
	// propose a block during this view.

	// Construct the QC and note that the BlockHash references the
	// previous block that we're about to build on top of.
	qc := QuorumCertificate{
		View:                           vote.View,
		BlockHash:                      vote.BlockHash, //Just for testing purposes.
		CombinedViewBlockHashSignature: BLSMultiSignature{[]byte("a"), []byte("a")},
	}

	// Construct the block
	block := Block{
		ProposerPublicKey: *node.PubKey,
		Txns:              GenerateTxns(10),
		View:              node.CurView,
		QC:                qc,
		AggregateQC: AggregateQC{
			View:                               0,
			ValidatorTimeoutHighQC:             QuorumCertificate{},
			ValidatorTimeoutHighQCViews:        nil,
			ValidatorCombinedTimeoutSignatures: BLSMultiSignature{[]byte("a"), []byte("a")},
		},
	}

	// Sign the block using the leader’s private key.
	block.ProposerSignature, _ = Sign(Hash(block.View, block.Txns), *node.PrivKey)
	Broadcast(block)
}

// validateTimeout is used to verify a timeout message.
func (node *Node) validateTimeout(timeout TimeoutMessage) bool {
	// Make sure that the validator is registered.
	if !verifyValidatorPublicKey(timeout.ValidatorPublicKey, node.ValidatorPubKeys) {
		return false
	}

	// Verify the HighQC in the timeout message
	if !node.validateQuorumCertificate(timeout.HighQC) {
		return false
	}

	// Verify the validator signature
	payload := Hash(timeout.View, nil)
	if !VerifySignature(payload, timeout.ValidatorPublicKey, timeout.PartialTimeoutViewSignature) {
		return false
	}

	return true
}

// AppendTimeoutMessage adds timeout message to our internal timeoutsSeen data structure.
func (node *Node) AppendTimeoutMessage(timeout TimeoutMessage) {

	// Check if the outer key exists in the map
	innerMap, ok := node.timeoutsSeen.Timeouts[Hash(timeout.View, nil)]
	if !ok {
		// Initialize the inner map if it doesn't exist
		innerMap = make(map[string]TimeoutMessage)
		node.timeoutsSeen.Timeouts[Hash(timeout.View, nil)] = innerMap
	}

	// Check if the inner key exists in the inner map
	_, ok = innerMap[string(timeout.ValidatorPublicKey)]
	if ok {
		// If the inner key exists, the validator has already sent a timeout message for the given
		// (view, highQC.blockHash) pair and the new timeout message should be rejected.
		return
	}

	// Add the new timeout message to the inner map
	innerMap[string(timeout.ValidatorPublicKey)] = timeout
}

// The handleTimeoutMessageFromPeer is called whenever we receive a timeout from a peer.
func (node *Node) handleTimeoutMessageFromPeer(timeoutMsg TimeoutMessage) {

	// If we're not the leader, ignore all timeout messages.
	if !node.IsLeader(timeoutMsg.View) {
		return
	}

	// Make sure that the timeoutMsg is for the most recent view and validate all of
	// its signatures, including those for its HighQC. We also run a check to make
	// sure we didn’t already receive a timeout or another vote from this peer.
	if !node.validateTimeout(timeoutMsg) {
		return
	}

	// If we get here, it means we are the leader so add the timeoutMsg to our
	// map of timeouts seen.
	node.AppendTimeoutMessage(timeoutMsg)
	// Check if we’ve gathered timeouts from 2/3rds of the validators, weighted
	// by stake.
	messages := node.timeoutsSeen.Timeouts[Hash(timeoutMsg.View, timeoutMsg.HighQC.View)]
	timeoutStake := ComputeStake(messages, node.PubKeyToStake)

	if timeoutStake < 2/3*GetTotalStake(node.PubKeyToStake) {
		return
	}

	// If we get here, it means we have enough timeouts to know that we can
	// propose a block during this view.

	// In order to construct the block, we will need to construct an AggregateQC
	// to prove that everyone timed out according to expectations. We compute a
	// validatorHighQCs list of all the QCs sent to use by the validators, along
	// with their signatures. We also find the QC with the highest view among the
	// validatorHighQCs.
	timeoutsSeen := node.timeoutsSeen.Timeouts[Hash(timeoutMsg.View, nil)]
	highQC := GetHighestViewHighQC(timeoutsSeen)
	views := GetTimeouthighQcViews(timeoutsSeen)
	// Construct the AggregateQC for this view.
	aggregateQC := AggregateQC{
		View:                               timeoutMsg.View,
		ValidatorTimeoutHighQC:             highQC,
		ValidatorTimeoutHighQCViews:        views,
		ValidatorCombinedTimeoutSignatures: BLSMultiSignature{[]byte("a"), []byte("a")},
	}

	// Construct the block and include the aggregateQC.
	block := Block{
		ProposerPublicKey: *node.PubKey,
		Txns:              GenerateTxns(10),
		View:              node.CurView,
		// Setting the QC is technically redundant when we have an AggregateQC but
		// we set it anyway for convenience.
		QC:          highQC,
		AggregateQC: aggregateQC,
	}

	// Sign the block using the leader’s private key.
	block.ProposerSignature, _ = Sign(Hash(block.View, block.Txns), *node.PrivKey)
	// Blast the block to everyone including yourself. This means we'll process
	// this block in handleBlockFromPeer, where we'll also update our highestQC and
	// advance to the next view.
	Broadcast(block)
}

// GetHighestViewHighQC returns the highest view highQC from the timeout messages.
func GetHighestViewHighQC(timeoutSeen map[string]TimeoutMessage) QuorumCertificate {
	highestView := uint64(0)
	var highestHighQC QuorumCertificate

	for _, timeout := range timeoutSeen {
		if timeout.HighQC.View > highestView {
			highestView = timeout.HighQC.View
			highestHighQC = timeout.HighQC

		}
	}

	return highestHighQC
}

// GetTimeouthighQcViews returns the views of the highQCs from the timeout messages.
func GetTimeouthighQcViews(timeoutSeen map[string]TimeoutMessage) []uint64 {
	views := []uint64{}

	for _, timeout := range timeoutSeen {
		views = append(views, timeout.HighQC.View)
	}

	return views
}

// Timeout and Timers
type Timer struct {
	baseDuration time.Duration
	timer        *time.Timer
	retries      int
}

func NewTimer(baseDuration time.Duration) *Timer {
	return &Timer{
		baseDuration: baseDuration,
		retries:      0,
	}
}

func (t *Timer) Start(node *Node) {
	t.timer = time.AfterFunc(t.getDuration(), func() {
		t.onTimeout(node)
	})
}

func (t *Timer) Stop() {
	if t.timer != nil {
		t.timer.Stop()
	}
}

// After a successful view Reset() is called. Number of retries is 0 so that we get the base duration when
// getDuration() is called.
func (t *Timer) Reset() {
	t.Stop()
	t.retries = 0
	t.timer.Reset(t.getDuration())
}

// Duration gets doubled each time when onTimeout(). It's function of the number of retries.
func (t *Timer) onTimeout(node *Node) {

	t.retries = t.retries + 1
	node.CurView = node.CurView + 1
	timeoutMsg := t.CreateTimeout_msg(node)
	leader, _ := computeLeader(node.CurView+1, node.PubKeyToStake)
	Send(timeoutMsg, PublicKey(leader))
	//To avoid voting in this view.
	node.Last_voted_view = uint64(math.Max(float64(node.Last_voted_view), float64(node.CurView)))
	t.Stop()
	t.Start(node)
}

func (t *Timer) getDuration() time.Duration {
	return t.baseDuration * time.Duration(1<<uint(t.retries))
}

func (t *Timer) CreateTimeout_msg(node *Node) *TimeoutMessage {
	sig, _ := Sign(Hash(node.CurView, node.HighestQC.View), *node.PrivKey)
	return &TimeoutMessage{
		ValidatorPublicKey:          *node.PubKey,
		View:                        node.CurView,
		HighQC:                      *node.HighestQC,
		PartialTimeoutViewSignature: sig,
	}

}
