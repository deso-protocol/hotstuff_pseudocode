package main

// This corresponds to the Algorithm 3 in the Fast-HotStuff
// paper https://arxiv.org/pdf/2010.11454.pdf

// Signature represents a standard public/private key
// signature (e.g. an ECDSA signature)
type Signature []byte

// PublicKey and PrivateKey represent a standard public/private key (e.g. an
// ECDSA key pair like is used in Bitcoin or DeSo).
type PublicKey []byte
type PrivateKey []byte

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
	ViewBlockHashSignature Signature
}

// A QuorumCertificate is a collection of signatures from 2/3rds of the validators
// on the network, weighted by Stake. The signatures are associated with a particular
// block and a particular view in which that block was proposed.
type QuorumCertificate struct {

	// The hash of the block that this QuorumCertificate authorizes.
	BlockHash [32]byte

	// The view corresponding to the block that this QuorumCertificate authorizes.
	View uint64

	// VoteViewBlockHashSignatures is a list of signatures pulled directly from validators'
	// VoteMessages received by the leader. Each signature is made on the
	// (View, BlockHash) pair specified above. The list of signatures represents a set
	// of validators who together own at least 2/3rds of the total stake on the network.
	VoteViewBlockHashSignatures []Signature

	// VoteValidatorPublicKeys is a list of public keys corresponding to the list of
	// VoteViewBlockHashSignatures. Each i-th public key is the signer of i-th block
	// hash signature.
	VoteValidatorPublicKeys []PublicKey
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
	// of. Remember that a QuorumCertificate is actually a *list* of signatures.
	HighQC QuorumCertificate

	// A signature of <View, HighQC> made with the validator’s key. This value gets
	// aggregated by the leader into an AggregateQC in the ValidatorHighQCSignatures
	// list.
	TimoutMsgSignature Signature
}

type TimeoutCertificate struct {
	View uint64

	TimeoutViewSignatures []Signature

	TimeoutValidatorPublicKeys []PublicKey
}

type TimeoutSyncMessage struct {
	ProposerPublicKey PublicKey

	HighQC QuorumCertificate

	TimeoutQC TimeoutCertificate

	TimeoutSyncProposerSignature Signature
}

type TimeoutSyncVoteMessage struct {
	ValidatorPublicKey PublicKey

	// Hash of <TimeoutSyncMessage.HighQC, TimeoutSyncMessage.TimeoutQC>
	TimeoutSyncMessageHash [32]byte

	Tag QCTag

	// Signature of <TimeoutSyncMessageHash, Tag>
	TimeoutSyncValidatorSignature Signature

	HighQC QuorumCertificate
}

// AggregateQC is an aggregation of timeout messages from 2/3rds of all validators,
// weighted by stake, that indicates that these validators want to time out a
// particular view.
//
// Instead of containing a list of *signatures*, like a
// QuorumCertificate does, the AggregateQC contains a list of *QuorumCertificates*,
// one for each validator that is timing out for this particular view (which means
// it's O(n^2) signatures, where n is the number of validators on the network).
//
// Each QuorumCertificate in the AggregateQC corresponds to the block with
// the *highest view* that each validator has seen. This allows the next leader to
// propose a block, while linking back to the most recent valid block that the
// 2/3rds of validators have seen (i.e. the block with the highest view).

type QCTag byte

const (
	HighQCTag = QCTag(0)
	LockQCTag = QCTag(1)
)

type AggregateQC struct {
	HighQC QuorumCertificate

	TimeoutQC TimeoutCertificate

	// Signature of <Hash(HighQC.ToBytes(), TimeoutQC.ToBytes()), HighQCTag>
	ValidatorsHighQCSignatures []Signature

	// Signature of <Hash(HighQC.ToBytes(), TimeoutQC.ToBytes()), LockQCTag>
	ValidatorsLockQCSignatures []Signature

	ValidatorsPublicKeys []PublicKey

	// Note that to check an AggregateQC, you need to verify that all signatures
	// are correct. This includes the ValidatorHiqhQCSignatures, as well as the
	// signatures in each QC inside of ValidatorHighQCs.
}

// Blocks are bundles of transactions proposed by the current leader.
//
// If the block from the previous view was a valid block that 2/3rds of validators
// have seen and validated, then the next block proposed by the leader will link
// back to that block by including a QuorumCertificate (QC), which is a bundle of
// VoteMessages from 2/3rds of validators, weighted by stake, indicating that
// these validators believe the previous block to be valid. This is the simple case
// where everything is running normally, with no timeouts, and the AggregateQC field
// will be left empty in this case.
//
// In the event that 2/3rds of validators timed out in the previous view, then the
// AggregateQC field will be constructed from TimeouteMessages received from 2/3rds
// of the validators. In this case, the QC will be set to the QC with the highest
// view number contained in the AggregateQC, since that is the most recent valid
// block that 2/3rds of validators have seen.
//
// The idea is that each block must link to the most recent valid block that 2/3rds
// of validators have seen. In normal conditions, the next leader will be able to
// assemble a QC directly from the VoteMessages they receive. In a timeout scenario,
// they will instead need to aggregate TimeoutMessages, and assemble them
// into an AggregateQC.
type Block struct {

	// The hash of the previous block that this block extends.
	PreviousBlockHash [32]byte

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
	ProposerSignature Signature
}

// === Some local variables ===

// The current validator's public and private keys, which should have been registered
// previously, and which should have stake allocated to them as well.
var myPublicKey, myPrivateKey = GetMyKeys()

// The timeout value is initially set to thirty seconds, and then doubled
// for each consecutive timeout the node experiences, which allows for other nodes
// to catch up in the event of a network disruption.
var timeoutSeconds = GetInitialTimeout()

// The ResetTimeout() function is not explicitly defined in this pseudocode, but
// it can be assumed to reset the timeout duration (see also WaitForTimeout() below).
ResetTimeout(timeoutSeconds)

// The highest QC that this node has seen so far. This is tracked so that the
// node can know when a block can be finalized, and so that the highest QC can
// be sent to the leader in the event of a timeout.
var highestQC *QuorumCertificate = nil

var lockedQC *QuorumCertificate = nil
var currentTimeoutSync TimeoutSyncMessage

// The networkChannel variable is a wrapper around peer connections. We will use
// it as an abstraction in this pseudocode to send and receive messages from
// other peers. For simplicity, we skip the implementation details of the p2p
// connections.
networkChannel = ConnectToPeers()

// The currentView variable stores the view that this node is currently on. We use the
// GetCurrentView() value in this pseudode instead of starting with 0 because
// we assume the network is in steady-state, rather than starting from the
// initial conditions, and we leave out all the details of getting in sync with
// other peers here as well.
currentView = GetCurrentView()


// The votesSeen variable stores a map of vote messages seen by the leader in the
// current view. We will make sure this map only stores votes for the currentView.
votesSeen = map[PublicKey]*VoteMessage{}

// The timeoutsSeen variable is similar to votesSeen. It stores the timeout messages
// seen by the leader in the current view. We also make sure this map only stores
// timeouts for the current view.
timeoutsSeen = map[PublicKey]*TimeoutMessage{}

timeoutsSyncVotesSeen = map[PublicKey]*TimeoutSyncVoteMessage{}

// The ResetTimeoutAndAdvanceView is used to reset the timeout duration, and the
// leader maps, as well as to increment the currentView. It’s called once a valid
// block has been produced for the view.
func ResetTimeoutAndAdvanceView(newTimeoutSeconds) {
	ResetTimeout(newTimeoutSeconds)
	AdvanceView()
}

// The AdvanceView function is used to reset the leader’s vote and timeout maps and
// increment the currentView.
func AdvanceView() {
	votesSeen.Reset()
	timeoutsSeen.Reset()
	timeoutsSyncVotesSeen.Reset()
	currentTimeoutSync = nil
	currentView += 1
}

// sanityCheckBlock is used to verify that the block contains valid information.
func sanityCheckBlock(block Block) bool {
	// Make sure the block is for the current view.
	//
	// Notice that with this code it is technically possible to receive a valid block
	// that has a view *less* than the current one. This can happen in a case where
	// you timeout, advance the view, and then it turns out that the block you
	// timed out on was able to form a QC. This is a general class of issues that is resolved
	// with block caching logic that is not included in this pseudocode. Generally,
	// you can assume that these situations where you receive a block from a previous
	// view are handled by the caching logic. The caching logic would need to essentially
	// do all of the same checks as we do here, but skip the checks that are specific to the
	// current view.
	//
	// In addition, it is possible to receive a block that is *ahead* of your current
	// view. This can happen in a case where the leader for the current view was able
	// to form a QC without your vote, before you were able to receive the block. Again
	// this is a general class of issues that is resolved with block caching logic that
	// is not included here. This case is simpler than the previous case because you
	// would simply not process the future block until downloading and processing the
	// previous block referred to by its QC.
	if block.View != currentView {
		return false
	}

	// Check that the block's proposer is the expected leader for the current view.
	if block.ProposerPublicKey != computeLeader(currentView) {
		return false
	}

	// Make sure the leader signed the block.
	if !verifySignature(block.Hash(), block.ProposerSignature, block.ProposerPublicKey) {
		return false
	}

	// The block's QC should never be empty.
	if block.QC == nil {
		return false
	}

	// We make sure the QC contains valid signatures from 2/3rds of validators, weighted by stake.
	if !validateQuorumCertificate(block.QC) {
		return false
	}

	// verifySignaturesAndTxns checks the transactions contained in the block are valid and have
	// correct signatures. We make sure that the block connects to the rest of the chain.
	if !verifySignaturesAndTxns(block) {
		return false
	}

	return true
}

func validateQuorumCertificate(qc QuorumCertificate) bool {
	if len(qc.VoteViewBlockHashSignatures) != len(qc.VoteValidatorPublicKeys) {
		return false
	}

	// Make sure that the validators included in the QC collectively own at least 2/3rds
	// of the stake. Also make sure there are no repeated public keys.
	if !ValidateSuperMajority(qc.VoteValidatorPublicKeys) {
		return false
	}

	// Make sure that the BlockHash in the qc matches our local BlockHash history.
	if GetBlockHashForView(qc.View) != qc.BlockHash {
		return false
	}

	// Iterate over all validator signatures and verify that they are correct.
	// The signatures should be made on the <view, blockHash> pairs.
	for ii := 0; ii < len(qc.VoteViewBlockHashSignatures); ii++ {
		payload := Hash(qc.View, qc.BlockHash)
		if !VerifySignature(payload, qc.VoteViewBlockHashSignatures[ii],
			qc.VoteValidatorPublicKeys[ii]) {

			return false
		}
	}

	return true
}

func validateTimeoutCertificate(tc TimeoutCertificate) bool {
	if len(tc.VoteViewBlockHashSignatures) != len(tc.VoteValidatorPublicKeys) {
		return false
	}

	// Make sure that the validators included in the QC collectively own at least 2/3rds
	// of the stake. Also make sure there are no repeated public keys.
	if !ValidateSuperMajority(tc.VoteValidatorPublicKeys) {
		return false
	}

	// Iterate over all validator signatures and verify that they are correct.
	// The signatures should be made on the <view, blockHash> pairs.
	for ii := 0; ii < len(tc.VoteViewBlockHashSignatures); ii++ {
		payload := Hash(qc.View)
		if !VerifySignature(payload, tc.VoteViewBlockHashSignatures[ii],
			tc.VoteValidatorPublicKeys[ii]) {

			return false
		}
	}

	return true
}

func validateAggregateQC(aggregateQC AggregateQC) bool {
	// Make sure the lists in the AggregateQC have correct lengths.
	if len(aggregateQC.ValidatorsHighQCSignatures)+len(aggregateQC.ValidatorsLockQCSignatures) !=
		len(aggregateQC.ValidatorsPublicKeys) {

		return false
	}

	// Make sure that the validators included in the QC collectively own at least 2/3rds
	// of the stake. Also make sure there are no repeated public keys.
	if !ValidateSuperMajority(aggregateQC.ValidatorsPublicKeys) {
		return false
	}

	if !validateQuorumCertificate(aggregateQC.HighQC) {
		return false
	}

	if !validateTimeoutCertificate(aggregateQC.TimeoutQC) {
		return false
	}

	// Iterate over all votes of validators who have a higher QC.
	timeoutSyncMessageHash := getTimeoutSyncMessageHash(aggregateQC.HighQC, aggregateQC.TimeoutQC)
	validatorsSignaturesList, qcTagList, validatorsPublicKeysList := FormatAggregateSignaturesIntoList(
		aggregateQC.ValidatorsHighQCSignatures, aggregateQC.ValidatorsLockQCSignatures, aggregateQC.ValidatorsPublicKeys)
	for ii := 0; ii < len(validatorsPublicKeysList); ii++ {
		// Verify that each signature in ValidatorHighQCSignatures is a valid validator
		// signature on the <View, QC> pair.
		validatorPublicKey := validatorsPublicKeysList[ii]
		validatorSignature := validatorsSignaturesList[ii]
		qcTag := qcTagList[ii]
		payload := Hash(timeoutSyncMessageHash, qcTag)
		if !verifySignature(payload, validatorSignature, validatorPublicKey) {

			return false
		}
	}

	return true
}

func updateLocalQCs(currentBlock Block) {
	// We update the highestQC if the block we received has one with a higher view.
	// In the case where we have an AggregateQC, remember that B_current.QC will
	// line up with the highest QC contained within the AggregateQC.
	B1 := GetBlockForHash(currentBlock.QC.BlockHash)
	B2 := GetBlockForHash(B1.QC.BlockHash)
	B3 := GetBlockForHash(B2.QC.BlockHash)

	if currentBlock.QC.View > highestQC.View {
		highestQC = B_current.QC
	}

	if currentBlock.View == B1.View+1 && B1.View == B2.View+1 {
		lockedQC = B1.QC
	}
}

// The handleBlockFromPeer is called whenever we receive a block from a peer.
func handleBlockMessageFromPeer(block *Block) {
	// Make sure that the block contains a valid QC, signature, transactions,
	// and that it's for the current view.
	if !sanityCheckBlock(block) {
		return
	}

	// The safeVote variable will tell us if we can vote on this block.
	safeVote := false

	// If the block doesn’t contain an AggregateQC, then that indicates that we
	// did NOT timeout in the previous view, which means we should just check that
	// the QC corresponds to the previous view.
	if block.AggregateQC == nil {
		// The block is safe to vote on if it is a direct child of the previous
		// block. This means that the parent and child blocks have consecutive
		// views. We use the current block’s QC to find the view of the parent.
		safeVote = block.View == block.QC.View+1
	} else {
		// If we have an AggregateQC set on the block, it means the nodes decided
		// to skip a view by sending TimeoutMessages to the leader, so we process
		// the block accordingly.

		// First we make sure the block contains a valid AggregateQC.
		validateAggregateQC(block.AggregateQC)
		// We find the QC with the highest view among the QCs contained in the
		// AggregateQC.

		highQCBlock := GetBlockForHash(block.QC.BlockHash)
		if len(block.AggregateQC.ValidatorsLockQCSignatures) > 0 {
			aggregateHighQCBlock := GetBlockForHash(block.AggregateQC.HighQC.BlockHash)
			// Check if highQCBlock is a child of the aggregateHighQCBlock.
			// The QC in the block should build on top of the highQC contained in the aggregateQC.
			safeVote = highQCBlock.IsChild(aggregateHighQCBlock)
		} else {
			safeVote = block.QC.ToBytes() == block.AggregateQC.HighQC.ToBytes()
		}

		// Make sure the block uses a higher QC than the lockedQC.
		if block.QC.View < lockedQC.View {
			safeVote = false
		}

		// We make sure that the block’s QC matches the highest QC that we’re
		// aware of. Notice that we need to check that all of the votes match up
		// across the two QCs, not just that the views line up, which is why we call
		// ToBytes() to do a "deep equal" comparison. This is because a
		// malicious leader could potentially produce two different QCs for the
		// same block by moving the votes around, which would then cause the blocks
		// to have different hashes.
	}

	// If safeVote is true, we will vote on the block.
	if safeVote {
		// Construct the vote message. The vote will contain the validator's
		// signature on the <view, blockHash> pair.
		payload := Hash(block.View, block.Hash())
		blockHashSignature := Sign(payload, myPrivateKey)

		voteMsg := VoteMessage{
			ValidatorPublicKey: myPublicKey,
			View:               block.View,
			BlockHash:          block.Hash(),
			BlockHashSignature: blockHashSignature,
		}
		// Send the vote directly to the next leader.
		Send(voteMsg, computeLeader(currentView+1))
		// We can now proceed to the next view.
		ResetTimeoutAndAdvanceView(GetInitialTimeout())
	}

	// Our commit rule relies on the fact that blocks were produced without timeouts.
	// Check if the chain looks like this:
	// B2 - B1 - B_current (current block) and B2 doesn't have an AggregateQC
	updateLocalQCs(block)

	B1 := GetBlockForHash(block.QC.BlockHash)
	B2 := GetBlockForHash(B1.QC.BlockHash)
	// Check that B2 is a direct child of B1.
	if block.View == B1.View+1 && B1.View == B2.View+1 && B2.AggregateQC == nil {
		// A direct chain is formed between B1 and B2, reinforced by the QC
		// in B_current. This means we should commit all blocks up to and including
		// block B1.
		CommitUpToBlock(B2)
	}
}

func validateVote(vote VoteMessage) bool {
	// Make sure the vote is made on the block in the previous view.
	if vote.View != currentView-1 {
		return false
	}

	// Make sure that the validator is registered.
	if !verifyValidatorPublicKey(vote.ValidatorPublicKey) {
		return false
	}

	// Make sure that the BlockHash in the view matches our local BlockHash history.
	if GetBlockHashForView(vote.View) != vote.BlockHash {
		return false
	}

	// Now verify the <view, BlockHash> signature
	payload := Hash(vote.View, vote.BlockHash)
	if !VerifySignature(payload, vote.ValidatorPublicKey, vote.BlockHashSignature) {
		return false
	}

	return true
}

// The handleVoteMessageFromPeer is called whenever we receive a vote from a peer.
func handleVoteMessageFromPeer(vote *VoteMessage) {
	// If we're not the leader, ignore all votes.
	if !IsLeader(currentView) {
		return
	}

	// Make sure that the vote is for the currentView and validate
	// the vote’s signature. We also run a check to make sure we didn’t
	// already receive a timeout or another vote from this peer.
	if !validateVote(vote) {
		return
	}

	// If we get here, it means we are the leader so add the vote to our map of
	// votes seen.
	votesSeen[vote.ValidatorPublicKey] = vote

	// Check if we’ve gathered votes from 2/3rds of the validators, weighted by stake.
	if ComputeVoteStake(votesSeen) < 2/3*GetTotalStake() {
		return
	}

	// At this point, we have collected enough votes to know that we can
	// propose a block during this view.

	// Construct the QC and note that the BlockHash references the
	// previous block that we're about to build on top of.
	qc := QuorumCertificate{
		View:                        vote.View,
		BlockHash:                   vote.BlockHash,
		VoteViewBlockHashSignatures: MapToList(votesSeen),
		VoteValidatorPublicKeys:     MapKeysToList(votesSeen),
	}

	// Construct the block
	block := Block{
		PreviousBlockHash: qc.BlockHash,
		ProposerPublicKey: myPublicKey,
		Txns:              GetTxns(),
		View:              currentView,
		QC:                qc,
		AggregateQC:       nil,
	}

	// Sign the block using the leader’s private key.
	block.ProposerSignature = Sign(block.Hash(), myPrivateKey)
	// Blast the block to everyone including yourself. This means we'll process
	// this block in handleBlockFromPeer, where we'll also update our highestQC and
	// advance to the next view. As such, there is no reason to
	// call ResetTimeoutAndAdvanceView() here.
	broadcast(block)
}

func validateTimeout(timeout TimeoutMessage) bool {
	// Make sure that the validator is registered.
	if !verifyValidatorPublicKey(vote.ValidatorPublicKey) {
		return false
	}

	// Verify the highQC in the timeout message
	if !validateQuorumCertificate(timeout.HighQC) {
		return false
	}

	// Verify the validator signature
	payload := Hash(view, timeout.HighQC.ToBytes())
	if !VerifySignature(payload, timeout.ValidatorPublicKey, timeout.TimoutMsgSignature) {
		return false
	}

	return true
}

// The handleTimeoutMessageFromPeer is called whenever we receive a timeout
// from a peer.
func handleTimeoutMessageFromPeer(timeoutMsg TimeoutMessage) {
	// If we're not the leader, ignore all timeout messages.
	if !IsLeader(vote.View) {
		return
	}

	// Make sure that the timeoutMsg is for the most recent view and validate all of
	// its signatures, including those for its HighQC. We also run a check to make
	// sure we didn’t already receive a timeout or another vote from this peer.
	if !validateTimeout(timeoutMsg) {
		return
	}

	// If we get here, it means we are the leader so add the timeoutMsg to our
	// map of timeouts seen.
	timeoutsSeen[timeoutMsg.ValidatorPublicKey] = timeoutMsg

	// Check if we’ve gathered timeouts from 2/3rds of the validators, weighted
	// by stake.
	if ComputeTimeoutStake(timeoutsSeen) < 2/3*GetTotalStake() {
		return
	}

	// If we get here, it means we have enough timeouts to know that we can
	// propose a block during this view.

	// In order to construct the block, we will need to construct an AggregateQC
	// to prove that everyone timed out according to expectations. We compute a
	// validatorHighQCs list of all the QCs sent to use by the validators, along
	// with their signatures. We also find the QC with the highest view among the
	// validatorHighQCs.
	validatorHighestQC, timeoutQC := FormatTimeoutsSeen(timeoutsSeen)
	// Construct the AggregateQC for this view.
	timeoutSyncMessage := TimeoutSyncMessage{
		ProposerPublicKey: myPublicKey,
		View:              currentView,
		HighQC:            validatorHighestQC,
		TimeoutQC:         timeoutQC,
	}
	timeoutSyncMessage.TimeoutSyncProposerSignature = Sign(timeoutSyncMessage.Hash(), myPrivateKey)

	broadcast(timeoutSyncMessage)
}

func validateTimeoutSync(timeoutSyncMsg TimeoutSyncMessage) bool {
	if timeoutSyncMsg.TimeoutQC.View != currentView {
		return false
	}

	if timeoutSyncMsg.ProposerPublicKey != computeLeader(currentView) {
		return false
	}

	if !verifySignature(timeoutSyncMsg.Hash(), timeoutSyncMsg.TimeoutSyncProposerSignature,
		timeoutSyncMsg.ProposerPublicKey) {
		return false
	}

	if !validateQuorumCertificate(timeoutSyncMsg.HighQC) {
		return false
	}

	if !validateTimeoutCertificate(timeoutSyncMsg.TimeoutQC) {
		return false
	}

	return true
}

func getTimeoutSyncMessageHash(highQC QuorumCertificate, timeoutQC TimeoutCertificate) []byte {
	return Hash(timeoutSyncMsg.HighQC, timeoutSyncMsg.TimeoutQC)
}

func sendTimeoutVote(timeoutSyncMsg TimeoutSyncMessage, tag QCTag) {

	timeoutSyncMessageHash := getTimeoutSyncMessageHash(timeoutSyncMsg.HighQC, timeoutSyncMsg.TimeoutQC)
	timeoutSyncVote := TimeoutSyncVoteMessage{
		ValidatorPublicKey:     myPublicKey,
		TimeoutSyncMessageHash: timeoutSyncMessageHash,
		Tag:                    tag,
		HighQC:                 highestQC,
	}
	timeoutSyncVote.TimeoutSyncValidatorSignature = Sign(Hash(timeoutSyncMessageHash, tag), myPrivateKey)

	Send(timeoutSyncVote, computeLeader(currentView))
}

func handleTimeoutSyncMessageFromPeer(timeoutSyncMsg TimeoutSyncMessage) {
	if !validateTimeoutSync(timeoutSyncMsg) {
		return
	}

	if timeoutSyncMsg.HighQC.View == lockedQC.View {
		sendTimeoutVote(timeoutSyncMsg, LockQCTag)
	} else if timeoutSyncMsg.HighQC.View > lockedQC.View {
		sendTimeoutVote(timeoutSyncMsg, HighQCTag)
	}
}

func validateTimeoutSyncMessageFromPeer(timeoutSyncVoteMsg TimeoutSyncVoteMessage) bool {
	if currentTimeoutSync == nil {
		return false
	}

	if timeoutSyncVoteMsg.TimeoutSyncMessageHash != currentTimeoutSync.Hash() {
		return false
	}

	payload := Hash(timeoutSyncVoteMsg.TimeoutSyncMessageHash, timeoutSyncVoteMsg.Tag)
	if !VerifySignature(payload, timeoutSyncVoteMsg.ValidatorPublicKey, timeoutSyncVoteMsg.TimeoutSyncValidatorSignature) {
		return false
	}

	if !validateQuorumCertificate(timeoutSyncVoteMsg.HighQC) {
		return false
	}

	if timeoutSyncVoteMsg.Tag == LockQCTag && timeoutSyncVoteMsg.HighQC.View <= currentTimeoutSync.HighQC.View {
		return false
	}

	return true
}

func handleTimeoutSyncVoteMessageFromPeer(timeoutSyncVoteMsg TimeoutSyncVoteMessage) {

	if !IsLeader(currentView) {
		return
	}

	if !validateTimeoutSync(timeoutSyncVoteMsg) {
		return
	}

	timeoutsSyncVotesSeen[timeoutSyncVoteMsg.ValidatorPublicKey] = timeoutSyncVoteMsg

	if timeoutSyncVoteMsg.HighQC.View > highestQC.View {
		highestQC = timeoutSyncVoteMsg.HighQC
	}

	if ComputeTimeoutStake(timeoutsSeen) < 2/3*GetTOtalStake() {
		return
	}

	timeoutSyncHighQCSignatures, timeoutSyncLockQCSignatures, validatorPublicKeys := FormatTimeoutSyncQC(timeoutsSyncVotesSeen)

	aggregateQC := AggregateQC{
		HighQC:                     currentTimeoutSync.HighQC,
		TimeoutQC:                  currentTimeoutSync.TimeoutQC,
		ValidatorsHighQCSignatures: timeoutSyncHighQCSignatures,
		ValidatorsLockQCSignatures: timeoutSyncLockQCSignatures,
		ValidatorsPublicKeys:       validatorPublicKeys,
	}

	block := Block{
		PreviousBlockHash: highestQC.BlockHash,
		ProposerPublicKey: myPublicKey,
		Txns:              GetTxns(),
		View:              currentView,
		QC:                highestQC,
		AggregateQC:       aggregateQC,
	}
	block.ProposerSignature = Sign(block.Hash(), myPrivateKey)

	broadcast(block)
}

// This is the node's main message and event handling loop. We continuously loop,
// incrementing the view with each round.
func StartConsensus() {
	// We run an infinite loop, and process each message from our peers as it
	// comes in. Note that the timeout is also something we might process as
	// part of this main loop. If you are unfamiliar with the concept of a "select"
	// statement, we recommend referencing Go's implementation here:
	// - https://golangdocs.com/select-statement-in-golang
	for {
		select {
		case messageFromPeer := <-networkChannel.WaitForMessage():
			if messageFromPeer.MessageType() == BlockMessageType {
				handleBlockMessageFromPeer(messageFromPeer)

			} else if messageFromPeer.MessageType() == VoteMessageType {
				handleVoteMessageFromPeer(messageFromPeer)

			} else if messageFromPeer.MessageType() == TimeoutMessageType {
				handleTimeoutMessageFromPeer(messageFromPeer)

			} else if messageFromPeer.MessageType() == TimeoutSyncMessageType {
				handleTimeoutSyncMessageFromPeer(messageFromPeer)

			} else if messageFromPeer.MessageType() == TimeoutSyncVoteMessageType {
				handleTimeoutSyncVoteMessageFromPeer(messageFromPeer)

			}
		case <-WaitForTimeout():
			// WaitForTimeout() is a function that will emit a value
			// whenever a timeout is triggered, causing us to enter this part
			// of the code. It can be assumed that calling
			// ResetTimeout(timeoutValue) will cause WaitForTimeout() to emit
			// a value after timeoutValue seconds have elapsed (ignoring all
			// previous calls to ResetTimeout()).

			// Construct the timeout message
			timeoutMsg := TimeoutMessage{
				ValidatorPublicKey: myPublicKey,
				View:               currentView,
				HighQC:             highestQC,
			}

			// Sign the timeout message and send it to the next leader .
			Sign(timeoutMsg, myPrivateKey)
			Send(timeoutMsg, computeLeader(currentView+1))

			// We use exponential backoff for timeouts in this reference
			// implementation.
			ResetTimeoutAndAdvanceView(2 * timeoutSeconds)
		case <-WaitForQuitSignal():
			Exit()
		}
	}
}
