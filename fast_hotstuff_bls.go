package fast_hotstuff

// This corresponds to the Algorithm 3 in the Fast-HotStuff
// paper https://arxiv.org/pdf/2010.11454.pdf

// A BLSPartialSignature is a signature typically made by a validator on a
// particular payload that can be combined with other signatures from other
// validators for the same or different payload. For example, if a hundred
// validators were to sign Hash(block1.ToBytes()), then all of those signatures
// could be combined using BLS into a single BLSMultiSignature. Using
// a multi-signature scheme, we're also able to combine signatures on
// different messages into one combined signature.
//
// Using BLS signatures is preferred because it's much more space-efficient
// and computationally efficient than using raw signatures. In addition to
// condensing n signatures down to a single O(1) value, verifying a
// combined BLS signature can be done with only one expensive signature
// check, as opposed to checking n signatures individually.
type BLSPartialSignature []byte

// A BLSMultiSignature is a multi-signature that is the result of combining multiple
// BLSPartialSignatures on the same payload. In order to verify a BLSMultiSignature,
// a validator needs the public keys of all of the validators whose signatures were
// combined. This is why a secondary field called ValidatorIDBitmap is included
// in this struct. It allows anyone who receives a BLSMultiSignature to check it
// by first looking up the public keys of all of the validators whose signatures were
// combined, and then verifying the BLSMultiSignature using those public keys.
// Along with the BLSMultiSignature, we also need to store the list of messages
// the were signed by the validators to make this multi-signature. We store this
// outside the BLSMultiSignature struct, in the AggregateQC.
//
// Importantly, while ValidatorIDBitmap technically requires O(n) space, where n is
// the number of validators, it can be compressed significantly using a bitmap that
// stores the indices of the validators whose signatures were combined. For
// example, because all validators are known at all times, a convention can be used
// whereby validators are sorted by their public keys. Then, the ValidatorIDBitmap
// is an n-bit number, where the i-th bit determines whether the i-th validator
// in the sorted list participated it the combined signature.
//
// This means that even if you have 10,000 validators involved in a signature, you will
// only need about a kilobyte of space to store the ValidatorIDBitmap, as the storage
// cost is asymptotically: 1 bit per validator.
type BLSMultiSignature struct {
	CombinedSignature byte
	ValidatorIDBitmap []byte
}

// For the purposes of this code, we will assume that PublicKey and PrivateKey can
// be used to sign and verify BLS signatures. Note that BLS signatures require a little
// more setup in order to be use-able, but that setup is not needed for the purposes of
// this pseudocode.
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
	TimeoutView uint64

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

	// The highest QC exctracted from all of the TimeoutMessages that the leader
	// received.
	ValidatorTimeoutHighQC QuorumCertificate

	// Here we include a list of the HighQC.View values we got from each of the
	// validators in the ValidatorTimeoutHighQCViews field. In addition, for each
	// unique HighQC.View value we received, we combine all the PartialTimeoutViewSignatures
	// for that HighQC.View into a single BLSMultiSignature.
	ValidatorTimeoutHighQCViews        []uint64
	ValidatorCombinedTimeoutSignatures BLSMultiSignature
}

// Blocks are bundles of transactions proposed by the current leader.
//
// If the block from the previous view was a valid block that 2/3rds of validators
// have seen and validated, then the next block proposed by the leader will link
// back to that block by including a QuorumCertificate (QC), which bundles signatures from
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
	ProposerSignature BLSPartialSignature
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
	if !VerifySignature(block.Hash(), block.ProposerPublicKey, block.ProposerSignature) {
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
	// Make sure that the validators included in the QC collectively own at least 2/3rds
	// of the stake. Also make sure there are no repeated public keys.
	// Note that we use the Bitmap contained in the combined signature to determine
	// which validators' signatures were used, and what their total stake was.
	if !ValidateSuperMajority(qc.CombinedViewBlockHashSignature) {
		return false
	}

	// Make sure that the BlockHash in the qc matches our local BlockHash history.
	if GetBlockHashForView(qc.View) != qc.BlockHash {
		return false
	}

	return true
}

func validateTimeoutProof(aggregateQC AggregateQC) bool {
	// Make sure that the validators included in the QC collectively own at least 2/3rds
	// of the stake. Also make sure there are no repeated public keys.
	// Note the bitmap in the signature allows us to determine how much stake the
	// validators had.
	if !ValidateSuperMajority(aggregateQC.ValidatorCombinedTimeoutSignatures) {
		return false
	}

	// Iterate over all the aggregate qc views and verify that the multi-signature is correct.
	var payloads [][]byte
	var highestQCView uint64
	for ii := 0; ii < len(aggregateQC.ValidatorTimeoutHighQCViews); ii++ {
		payload := Hash(aggregateQC.View, aggregateQC.ValidatorTimeoutHighQCViews[ii])
		payloads = append(payloads, payload)

		if aggregateQC.ValidatorTimeoutHighQCViews[ii] > highestQCView {
			highestQCView = aggregateQC.ValidatorTimeoutHighQCViews[ii]
		}
	}

	if !VerifyMultiSignature(payloads, aggregateQC.ValidatorCombinedTimeoutSignatures) {
		return false
	}

	// The highest QC view found in the signatures should match the highest view
	// of the HighestQC included in the AggregateQC.
	if highestQCView != aggregateQC.ValidatorTimeoutHighQC.View {
		return false
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
		validateTimeoutProof(block.AggregateQC)
		// We find the QC with the highest view among the QCs contained in the
		// AggregateQC.
		highestTimeoutQC := block.AggregateQC.ValidatorTimeoutHighQC
		// If our local highestQC has a smaller view than the highestTimeoutQC,
		// we update our local highestQC.
		if highestTimeoutQC.View > highestQC.View {
			highestQC = highestTimeoutQC
		}
		// We make sure that the block’s QC matches the view of the highest QC that we’re aware of.
		safeVote = block.QC.View == highestQC.View
	}

	// If safeVote is true, we will vote on the block.
	if safeVote {
		// Construct the vote message. The vote will contain the validator's
		// signature on the <view, blockHash> pair.
		payload := Hash(block.View, block.Hash())
		blockHashSignature := Sign(payload, myPrivateKey)

		voteMsg := VoteMessage{
			ValidatorPublicKey:            myPublicKey,
			View:                          block.View,
			BlockHash:                     block.Hash(),
			PartialViewBlockHashSignature: blockHashSignature,
		}
		// Send the vote directly to the next leader.
		Send(voteMsg, computeLeader(currentView+1))
		// We can now proceed to the next view.
		ResetTimeoutAndAdvanceView(GetInitialTimeout())
	}

	// Our commit rule relies on the fact that blocks were produced without timeouts.
	// Check if the chain looks like this:
	// B1 - B2 - ... - B_current (current block)
	// Where ... represent an arbitrary number of skipped views.
	B_current := block
	B2 := GetBlockForHash(block.QC.BlockHash)
	B1 := GetBlockForHash(B2.QC.BlockHash)

	// We update the highestQC if the block we received has one with a higher view.
	// In the case where we have an AggregateQC, remember that B_current.QC will
	// line up with the highest QC contained within the AggregateQC.
	if B_current.QC.View > highestQC.View {
		highestQC = B_current.QC
	}

	// Check that B2 is a direct child of B1.
	if B2.View == B1.View+1 {
		// A direct chain is formed between B1 and B2, reinforced by the QC
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
	if !VerifySignature(payload, vote.ValidatorPublicKey, vote.PartialViewBlockHashSignature) {
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
		View:                           vote.View,
		BlockHash:                      vote.BlockHash,
		CombinedViewBlockHashSignature: ConstructCombinedSignatureFromVotes(votesSeen),
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

	// Verify the HighQC in the timeout message
	if !validateQuorumCertificate(timeout.HighQC) {
		return false
	}

	// Verify the validator signature
	payload := Hash(view, timeout.HighQC.View)
	if !VerifySignature(payload, timeout.ValidatorPublicKey, timeout.PartialTimeoutViewSignature) {
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
	highQC, timeoutHighQCViews, timeoutHighQCCombinedSigs := FormatTimeoutQCs(timeoutsSeen)
	// Construct the AggregateQC for this view.
	aggregateQC := AggregateQC{
		View:                               timeoutMsg.TimeoutView,
		ValidatorTimeoutHighQC:             highQC,
		ValidatorTimeoutHighQCViews:        timeoutHighQCViews,
		ValidatorCombinedTimeoutSignatures: timeoutHighQCCombinedSigs,
	}

	// Construct the block and include the aggregateQC.
	block := Block{
		PreviousBlockHash: highQC.BlockHash,
		ProposerPublicKey: myPublicKey,
		Txns:              GetTxns(),
		View:              currentView,
		// Setting the QC is technically redundant when we have an AggregateQC but
		// we set it anyway for convenience.
		QC:          highQC,
		AggregateQC: aggregateQC,
	}

	// Sign the block using the leader’s private key.
	block.ProposerSignature = Sign(block, myPrivateKey)
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
				handleBlockFromPeer(messageFromPeer)

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
				ValidatorPublicKey:          myPublicKey,
				TimeoutView:                 currentView,
				HighQC:                      highestQC,
				PartialTimeoutViewSignature: Sign(Hash(currentView, highestQC.View), myPrivateKey),
			}

			// Send the timeout message and send it to the next leader .
			Send(timeoutMsg, computeLeader(currentView+1))

			// We use exponential backoff for timeouts in this reference
			// implementation.
			ResetTimeoutAndAdvanceView(2 * timeoutSeconds)
		case <-WaitForQuitSignal():
			Exit()
		}
	}
}
