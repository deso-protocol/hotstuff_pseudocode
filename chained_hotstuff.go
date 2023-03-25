package main

// This corresponds to the Algorithm 4 in the HotStuff
// paper https://arxiv.org/pdf/1803.05069.pdf

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
// validators, weighted by Stake, the leader can construct a TimeoutQC, which they
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

	// A signature of <View> made with the validator’s key. This value gets
	// aggregated by the leader into an TimeoutQC in the ValidatorHighQCSignatures
	// list.
	TimoutViewSignature Signature
}

// Block contains a bundle of transactions proposed by the current leader.
//
// The block links back to a previous block, forming a chain, by means of a
// QuorumCertificate (QC). The leader can create the QC by aggregating VoteMessages
// from 2/3rds of validators, weighted by stake.
//
// In the event that 2/3rds of validators timed out in the previous view, the leader
// will choose the highest QC that he's aware of. However, a malicious leader can
// also create a fork by branching out of validators' lockedQC, rather than highestQC.
//
// The idea is that each block must link to the most recent valid block that 2/3rds
// of validators have seen. In normal conditions, the next leader will be able to
// assemble a QC directly from the VoteMessages they receive.
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

// The lockedQC is a special safety QC used by validators to determine whether
// they can safely vote on a block. It is the QC with the second-highest view
// that we're aware of.
var lockedQC *QuorumCertificate = nil

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

// The handleBlockFromPeer is called whenever we receive a block from a peer.
func handleBlockFromPeer(block *Block) {
	// Make sure that the block contains a valid QC, signature, transactions,
	// and that it's for the current view.
	if !sanityCheckBlock(block) {
		return
	}

	// This condition checks whether a node can safely vote on a block.
	//
	// IsDescendant determines whether a block is a child of another block. In other
	// words it determines if two blocks are in the same fork.
	if IsDescendant(block, GetBlockForHash(lockedQC.BlockHash)) || block.QC.View > lockedQC.View {
		// If the block passes the above condition, the node can now vote.
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
	// B1 - B2 - B3 - ... - B_current (current block)
	// Where ... represent an arbitrary number of skipped views.
	B_current := block
	B3 := GetBlockForHash(block.QC.BlockHash)
	B2 := GetBlockForHash(B3.QC.BlockHash)
	B1 := GetBlockForHash(B2.QC.BlockHash)

	// We update the highestQC if the block we received has one with a higher view.
	if B_current.QC.View > highestQC.View {
		highestQC = B_current.QC
	}

	// We update the lockedQC if the second-highest QC in the chain of B_current has
	// a higher view than our current lockedQC.
	if B3.QC.View > lockedQC.View {
		lockedQC = B3.QC
	}

	// Check that B3 is a direct child of B2, and B2 is a direct child of B1.
	if B3.View == B2.View+1 && B2.View == B1.View+1 {
		// A direct 2-chain is formed between B1, B2, and B3, reinforced by the QC
		// in B_current. This means we should commit all blocks up to and including
		// block B1.
		CommitUpToBlock(B1)
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
	payload := Hash(view)
	if !VerifySignature(payload, timeout.ValidatorPublicKey, timeout.TimoutViewSignature) {
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

	// In order to construct the block, we find the QC with the highest view
	// from among the validators' timeout messages.
	timeoutsSeenList := MapToList(timeoutsSeen)
	for ii := 0; ii < len(timeoutsSeenList); ii++ {
		if timeoutsSeenList[ii].HighQC.View > highestQC.View {
			highestQC = timeoutsSeenList[ii].HighQC
		}
	}

	// Construct the block and include the highestQC.
	block := Block{
		PreviousBlockHash: highestQC.BlockHash,
		ProposerPublicKey: myPublicKey,
		Txns:              GetTxns(),
		View:              currentView,
		QC:                highestQC,
	}

	// Sign the block using the leader’s private key.
	block.Signature = Sign(block, myPrivateKey)
	// Blast the block to everyone including yourself. This means we'll process
	// this block in handleBlockFromPeer, where we'll also update our highestQC and
	// advance to the next view.
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
			Sign(Hash(currentView), myPrivateKey)
			Send(timeoutMsg, computeLeader(currentView+1))

			// We use exponential backoff for timeouts in this reference
			// implementation.
			ResetTimeoutAndAdvanceView(2 * timeoutSeconds)
		case <-WaitForQuitSignal():
			Exit()
		}
	}
}
