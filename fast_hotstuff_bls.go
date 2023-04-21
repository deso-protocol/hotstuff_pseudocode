package fast_hotstuff_bls

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math"
	"math/rand"
	"sort"
	"sync"
	"time"
)

// This corresponds to the Algorithm 3 in the Fast-HotStuff
// paper https://arxiv.org/pdf/2010.11454.pdf

// A BLSPartialSignature is a signature typically made by a validator on a
// particular payload that can be combined with other signatures from other
// validators for the same payload. For example, if a hundred validators
// were to sign Hash(block1.ToBytes()), then all of those signatures could
// be combined using BLS into a single BLSCombinedSignature.
//
// Using BLS signatures is preferred because it's much more space-efficient
// and computationally efficient than using raw signatures. In addition to
// condensing n signatures down to a single O(1) value, verifying a
// combined BLS signature can be done with only one expensive signature
// check, as opposed to checking n signatures individually.
type BLSPartialSignature []byte

// A BLSCombinedSignature is a signature that is the result of combining multiple
// BLSPartialSignatures on the same payload. In order to verify a BLSCombinedSignature,
// a validator needs the public keys of all of the validators whose signatures were
// combined. This is why a secondary field called ValidatorIDBitmap is included
// in this struct. It allows anyone who receives a BLSCombinedSignature to check it
// by first looking up the public keys of all of the validators whose signatures were
// combined, and then verifying the BLSCombinedSignature using those public keys.
//

// TxnMsg Just creating TxnMsg to avoid errors
type TxnMsg struct {
	From   string
	To     string
	Amount int
}

func GenerateTxns(n int) []TxnMsg {
	rand.Seed(time.Now().UnixNano())

	var txns []TxnMsg
	for i := 0; i < n; i++ {
		txns = append(txns, TxnMsg{
			From:   string(rand.Intn(1000)),
			To:     string(rand.Intn(1000)),
			Amount: rand.Intn(100),
		})
	}
	return txns
}

type Node struct {
	Id                  int
	CurView             uint64
	HighestQC           *QuorumCertificate
	PubKey              *PublicKey
	PrivKey             *PrivateKey
	PubKeys             []PublicKey
	LatestCommittedView uint64
	Last_voted_view     uint64
	PubKeyToStake       map[string]int
}

//	Importantly, while ValidatorIDBitmap technically requires O(n) space, where n is
//
// the number of validators, it can be compressed significantly using a bitmap that
// only stores the indices of thevalidators whose signatures were combined. For
// example, because all validators are known at all times, a convention can be used
// whereby validators are sorted by their public keys, and then the ValidatorIDBitmap
// is simply a bitmap that stores the indices of the validators whose signatures were
// combined.
//
// This means that even if you have 10,000 validators involved in a signature, you will
// only need about a kilobyte of space to store the ValidatorIDBitmap, which is only
// a little more than the size of a typical transaction on the network.
type BLSCombinedSignature struct {
	CombinedSignature []byte
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

	// This signature is a BLSCombinedSignature that is the result of combining
	// all of the PartialViewBlockHashSignatures from the VoteMessages that were
	// aggregated by a leader. Note that the signature includes the ValidatorIDBitmap
	// which the recipient can use to verify the signature and to verify the amount
	// of stake that the signers collectively own.
	CombinedViewBlockHashSignature BLSCombinedSignature
}

// Set of SafeBlocks and CommittedBlocks
type SafeBlockMap struct {
	Blocks map[[32]byte]*Block
	Mutex  sync.Mutex
}
type CommittedBlockMap struct {
	Block map[[32]byte]*Block
	Mutex sync.Mutex
}

func (aqc AggregateQC) isEmpty() bool {
	if aqc.View == 0 && aqc.ValidatorCombinedTimeoutSignatures.CombinedSignature == nil {
		return true

	}
	return false
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
// The AggregateQC contains the highest QC that all of the validators who timed out
// are aware of, and combined signatures from all of the validators who timed out.
//
// As one piece of additional complexity, note that the signatures of the validators
// cannot be naively aggregated into a single BLSCombinedSignature, as the signatures
// are on different payloads, i.e. different (TimeoutView, HighQC.View) pairs. Instead,
// the leader must group the signatures for each unique payload, and combine them
// together into a BLSCombinedSignature for each payload.
//
// Importantly, the number of signatures should generally be proportional to the
// number of views that have timed out. And so the AggregateQC should not generally
// be much larger than a normal QC.
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
	// for that HighQC.View into a single BLSCombinedSignature. The
	// ValidatorCombinedTimeoutSignatures array contains the combined signatures for
	// each of the unique views in ValidatorTimeoutHighQCViews.
	//todo: Discuss that bls can aggregate msgs with different payloads.
	//https://crypto.stanford.edu/~dabo/pubs/papers/BLSmultisig.html

	// Notice that we can't include a single BLSCombinedSignature for the entire
	// set of TimeoutMessages we received because we can only aggregate BLSPartialSignatures
	// that have the same payload, i.e. the same (TimeoutView, HighQC.View) pair.
	// This should generally be fine, however, because the number of unique HighQC.View
	// values should not generally exceed the number of timed-out views.
	ValidatorTimeoutHighQCViews []uint64
	//todo: Need to properly implemented as bls aggregated signature over timeoutMessage.View and
	//todo:list of timeoutMessage.HighQC.view
	ValidatorCombinedTimeoutSignatures BLSCombinedSignature
}

//  Blocks are bundles of transactions proposed by the current leader.
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

// Some  utility functions
func (node Node) GetMyKeys(mypubkey PublicKey, myprivkey PrivateKey) {
	node.PrivKey = &myprivkey
	node.PubKey = &mypubkey
}

func (Block) Hash() (hash [32]byte) {
	return hash
}

func VerifySignature(hash [32]byte, publicKey PublicKey, signature []byte) bool {
	return true
}

// ResetTimeout() resets timer for a specific duration. Duration is the funciton of the number of times
// the protocol observed failure. But it should be capped and grandually decreased to a normal acceptable
// value.
func (node *Node) ResetTimeout() {

}

// Compute the leader node for the given view number and list of public keys
func computeLeader(viewNum uint64, pubKeys []PublicKey) PublicKey {
	// Compute the hash of the view number as a byte slice
	viewHash := sha256.Sum256([]byte{byte(viewNum), byte(viewNum >> 8), byte(viewNum >> 16), byte(viewNum >> 24),
		byte(viewNum >> 32), byte(viewNum >> 40), byte(viewNum >> 48), byte(viewNum >> 56)})

	// Sort the public keys lexicographically
	sort.Slice(pubKeys, func(i, j int) bool {
		return bytes.Compare(pubKeys[i], pubKeys[j]) < 0
	})

	// Compute the index of the leader node as the least significant 8 bits of the hash
	idx := int(viewHash[31]) % len(pubKeys)

	// Return the public key of the leader node
	return pubKeys[idx]
}

func (node *Node) AmIaLeader(viewNum uint64) bool {
	pubkey := computeLeader(viewNum, node.PubKeys)
	if pubkey.Equals(*node.PubKey) {
		return true
	}
	return false
}

func Hash(x uint64, y interface{}) [32]byte {
	var buf []byte
	switch y := y.(type) {
	case uint64:
		buf = make([]byte, 8)
		binary.LittleEndian.PutUint64(buf, y)
	case []byte:
		buf = y
	default:
		panic("invalid type")
	}
	h := sha256.Sum256(append(buf, byte(x)))
	return h
}

func (pk PublicKey) Equals(other PublicKey) bool {
	return bytes.Equal(pk, other)
}

// TimoutDuration This function returns the duration. It should be noted that duration can be calculated as
// the function of number of failures.

// === Some local variables ===

// The current validator's public and private keys, which should have been registered
// previously, and which should have stake allocated to them as well.

// The timeout value is initially set to thirty seconds, and then doubled
// for each consecutive timeout the node experiences, which allows for other nodes
// to catch up in the event of a network disruption.

// I think this is too much detail for spec. You can decide on how to do it during implementation.
//var timeoutSeconds = GetInitialTimeout()

// The highest QC that this node has seen so far. This is tracked so that the
// node can know when a block can be finalized, and so that the highest QC can
// be sent to the leader in the event of a timeout.

// The networkChannel variable is a wrapper around peer connections. We will use
// it as an abstraction in this pseudocode to send and receive messages from
// other peers. For simplicity, we skip the implementation details of the p2p
// connections.

//networkChannel = ConnectToPeers()

// The currentView variable stores the view that this node is currently on. We use the
// GetCurrentView() value in this pseudode instead of starting with 0 because
// we assume the network is in steady-state, rather than starting from the
// initial conditions, and we leave out all the details of getting in sync with
// other peers here as well.

// The votesSeen variable stores a map of vote messages seen by the leader in the
// current view. We will make sure this map only stores votes for the currentView.
// Rev: We don't know if the current view of the node is the current view of majority of the network.
// It is map of the hash(block.view, block.hash) to map string (vote.voter)
type votesSeen map[[32]byte]map[string]VoteMessage

// The timeoutsSeen variable is similar to votesSeen. It stores the timeout messages
// seen by the leader in the current view. We also make sure this map only stores
// timeouts for the current view.

// Rev: We don't know if the current view of the node is the current view of majority of the network.
// It is map of the hash(block.view, block.hash) to map string (timeoutMessage.ValidatorPublickey)
type TimeoutsSeenMap map[[32]byte]map[string][]TimeoutMessage

func (m TimeoutsSeenMap) Reset(key [32]byte) {
	delete(m, key)
}

// Validates supermajority has voted in QC
func ValidateSuperMajority_QC(BLSCombinedSignature) bool {
	return true
}

// ValidateSuperMajority_AggQC Validate super majority has sent their timeout msgs
func ValidateSuperMajority_AggQC(BLSCombinedSignature) bool {
	//
	return true
}
func verifySignaturesAndTxns(block Block) bool {
	return true
}
func Sign(payload [32]byte, privKey PrivateKey) ([]byte, error) {
	//to be implemented
	return []byte(uint64(3)), nil
}

// The ResetTimeoutAndAdvanceView is used to reset the timeout duration, and the
// leader maps, as well as to increment the currentView. It’s called once a valid
// block has been produced for the view.

// The AdvanceView function is used to reset the leader’s vote and timeout maps and
// increment the currentView.

//votesSeen.Reset() and
//	TimeoutsSeenMap.Reset(certificate.View) can be called later whenever needed.

func (node Node) AdvanceView_qc(certificate QuorumCertificate) {
	certificate.View += 1
	node.ResetTimeout()
}

func (node Node) AdvanceView_Aggqc(agqc AggregateQC) {
	agqc.View += 1
	node.ResetTimeout()
}

// This functions is used to get index  of the signer of QC in the bitmap.
func getOnBitIndices(bitmap []byte) []int {
	indices := make([]int, 0)
	for i := 0; i < len(bitmap)*8; i++ {
		if getBitAtIndex(bitmap, i) {
			indices = append(indices, i)
		}
	}
	return indices
}

func getBitAtIndex(bitmap []byte, i int) bool {
	byteIndex := i / 8
	bitIndex := uint(i % 8)
	return bitmap[byteIndex]&(1<<bitIndex) != 0
}

func Send(msg VoteMessage, leader PublicKey) {

}

func GetBlockIDForView(view uint64, blockMap SafeBlockMap) ([32]byte, error) {
	for _, block := range blockMap.Blocks {
		if block.View == view {
			return block.Hash(), nil
		}
	}
	return [32]byte{}, fmt.Errorf("block not found for view %d", view)
}

func (node *Node) commitChainFromGrandParent(block *Block, safeblocks *SafeBlockMap, committedBlocks *CommittedBlockMap) {
	parent := safeblocks.Blocks[block.QC.BlockHash]
	if parent == nil {
		return
	}

	grandParent := safeblocks.Blocks[parent.QC.BlockHash]
	if grandParent == nil {
		return
	}

	if parent.View != (grandParent.View + 1) {
		return
	}

	for view := node.LatestCommittedView + 1; view <= grandParent.View; view++ {
		blockHash, err := GetBlockIDForView(view, *safeblocks)
		if err != nil {
			return
		}

		block, ok := safeblocks.Blocks[blockHash]
		if !ok {
			break
		}

		if _, ok := committedBlocks.Block[blockHash]; ok {
			continue
		}

		committedBlocks.Block[blockHash] = block
		node.LatestCommittedView = view
	}
}

// sanityCheckBlock is used to verify that the block contains valid information.
func sanityCheckBlock(block Block, node *Node) bool {
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
	if block.View < node.CurView {
		return false
	}

	if block.View <= node.Last_voted_view {
		//Have already voted for the block.
		return false
	}

	// Check that the block's proposer is the expected leader for the current view.
	if !block.ProposerPublicKey.Equals(computeLeader(block.View, node.PubKeys)) {
		return false
	}

	// Make sure the leader signed the block.
	if !VerifySignature(block.Hash(), block.ProposerPublicKey, block.ProposerSignature) {
		return false
	}

	// The block's QC should never be empty.
	if &block.QC == nil {
		return false
	}

	// We make sure the QC contains valid signatures from 2/3rds of validators, weighted by stake.
	if !ValidateSuperMajority_QC(block.QC.CombinedViewBlockHashSignature) {
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
	if !ValidateSuperMajority_QC(qc.CombinedViewBlockHashSignature) {
		return false
	}

	// Make sure that the BlockHash in the qc matches our local BlockHash history.
	//Rev: It is not possible to have a valid quorum certificate and different blockchain history
	// Hence, this check is not necessary.
	//if GetBlockHashForView(qc.View) != qc.BlockHash {
	//	return false
	//	}

	return true
}

// todo: This function needs to be revised
func validateTimeoutProof(aggregateQC AggregateQC, pubkeys []PublicKey) bool {
	// Make sure the lists in the AggregateQC have equal lengths
	if len(aggregateQC.ValidatorTimeoutHighQCViews) != len(aggregateQC.ValidatorCombinedTimeoutSignatures.ValidatorIDBitmap) {
		return false
	}

	// Make sure that the validators included in the QC collectively own at least 2/3rds
	// of the stake. Also make sure there are no repeated public keys.
	// Note the bitmap in the signature allows us to determine how much stake the
	// validators had.
	if !ValidateSuperMajority_AggQC(aggregateQC.ValidatorCombinedTimeoutSignatures) {
		return false
	}

	// Iterate over all the aggregate qc signatures and verify that the signatures are correct.

	// Rev: Don't need to iterate over all the signatures. Just verify the highQC and the
	// aggregated signature of the aggregatedQC.
	highestQCView := uint64(0)

	//for ii := 0; ii < len(aggregateQC.ValidatorTimeoutHighQCViews); ii++ {
	//	payload := Hash(aggregateQC.View, aggregateQC.ValidatorTimeoutHighQCViews[ii])
	//	if !VerifySignature(payload, ,aggregateQC.ValidatorCombinedTimeoutSignatures[ii]) {
	//		return false
	//	}
	//	if aggregateQC.ValidatorTimeoutHighQCViews[ii] > highestQCView {
	//		highestQCView = aggregateQC.ValidatorTimeoutHighQCViews[ii]
	//	}
	//	}

	// The highest QC view found in the signatures should match the highest view
	// of the HighestQC included in the AggregateQC.
	if highestQCView != aggregateQC.ValidatorTimeoutHighQC.View {
		return false
	}

	return true
}

func (sbm *SafeBlockMap) Put(block *Block) {
	sbm.Mutex.Lock()
	defer sbm.Mutex.Unlock()
	sbm.Blocks[block.Hash()] = block
}

// The handleBlockFromPeer is called whenever we receive a block from a peer.
func handleBlockFromPeer(block *Block, node *Node, safeblocks *SafeBlockMap, committedblocks *CommittedBlockMap) {
	// Make sure that the block contains a valid QC, signature, transactions,
	// and that it's for the current view.
	if !sanityCheckBlock(*block, node) {
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
		node.AdvanceView_qc(block.QC)
	} else {
		// If we have an AggregateQC set on the block, it means the nodes decided
		// to skip a view by sending TimeoutMessages to the leader, so we process
		// the block accordingly.

		// First we make sure the block contains a valid AggregateQC.
		validateTimeoutProof(block.AggregateQC, node.PubKeys)
		// We find the QC with the highest view among the QCs contained in the
		// AggregateQC.
		highestTimeoutQC := block.AggregateQC.ValidatorTimeoutHighQC
		// If our local highestQC has a smaller view than the highestTimeoutQC,
		// we update our local highestQC.
		if highestTimeoutQC.View > node.HighestQC.View {
			node.HighestQC = &(highestTimeoutQC)
		}
		// We make sure that the block’s QC matches the view of the highest QC that we’re aware of.
		safeVote = block.QC.View == node.HighestQC.View
		node.AdvanceView_Aggqc(block.AggregateQC)
	}

	// If safeVote is true, we will vote on the block.
	if safeVote {
		// Construct the vote message. The vote will contain the validator's
		// signature on the <view, blockHash> pair.
		payload := Hash(block.View, block.Hash())
		blockHashSignature, _ := Sign(payload, *node.PrivKey)

		voteMsg := VoteMessage{
			ValidatorPublicKey:            *node.PubKey,
			View:                          block.View,
			BlockHash:                     block.Hash(),
			PartialViewBlockHashSignature: blockHashSignature,
		}
		// Send the vote directly to the next leader.
		Send(voteMsg, computeLeader(node.CurView+1, node.PubKeys))
		// We can now proceed to the next view.
		node.AdvanceView_qc(block.QC)
		node.Last_voted_view = uint64(math.Max(float64(node.Last_voted_view), float64(node.CurView)))

		// Add the block to the safeblocks struct.
		safeblocks.Put(block)
	}

	// Our commit rule relies on the fact that blocks were produced without timeouts.
	// Check if the chain looks like this:
	// B1 - B2 - ... - B_current (current block)
	// Where ... represent an arbitrary number of skipped views.

	node.commitChainFromGrandParent(block, safeblocks, committedblocks)
}

func verifyValidatorPublicKey(validatorPublicKey PublicKey, publicKeys []PublicKey) bool {
	for _, publicKey := range publicKeys {
		if bytes.Equal(publicKey[:], validatorPublicKey[:]) {
			return true
		}
	}
	return false
}

func validateVote(vote VoteMessage, node *Node, safeblocks *SafeBlockMap) bool {
	// Make sure the vote is made on the block in the previous view.
	if vote.View < node.CurView {
		return false
	}

	// Make sure that the validator is registered.
	if !verifyValidatorPublicKey(vote.ValidatorPublicKey, node.PubKeys) {
		return false
	}

	// Make sure that the BlockHash in the view matches our local BlockHash history.
	blockHash, err := GetBlockIDForView(vote.View, (*safeblocks))
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
func ComputeStake(messages interface{}, pubKeyToStake map[string]int) int {
	totalStake := 0
	switch m := messages.(type) {
	case map[string]VoteMessage:
		for _, vote := range m {
			if stake, exists := pubKeyToStake[string(vote.ValidatorPublicKey)]; exists {
				totalStake += stake
			}
		}
	case map[string]TimeoutMessage:
		for _, timeout := range m {
			if stake, exists := pubKeyToStake[string(timeout.ValidatorPublicKey)]; exists {
				totalStake += stake
			}
		}
	}
	return totalStake
}

// In correct need to be fixed. Validator public key
func AppendVoteMessage(votesSeen *map[[32]byte]map[string]VoteMessage, vote VoteMessage) {
	// Check if the outer key exists in the map
	innerMap, ok := (*votesSeen)[Hash(vote.View, vote.BlockHash)]
	if !ok {
		// Initialize the inner map if it doesn't exist
		innerMap = make(map[string]VoteMessage)
		(*votesSeen)[Hash(vote.View, vote.BlockHash)] = innerMap
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

func GetTotalStake(pubKeyToStake map[string]int) int {
	totalStake := 0
	for _, stake := range pubKeyToStake {
		totalStake += stake
	}
	return totalStake
}

// The handleVoteMessageFromPeer is called whenever we receive a vote from a peer.
func handleVoteMessageFromPeer(vote *VoteMessage, node *Node, safeblocks *SafeBlockMap, voteseen *map[[32]byte]map[string]VoteMessage) {
	// If we're not the leader, ignore all votes.
	if !node.AmIaLeader(vote.View + 1) {
		return
	}

	// Make sure that the vote is for the currentView and validate
	// the vote’s signature. We also run a check to make sure we didn’t
	// already receive a timeout or another vote from this peer.
	if !validateVote(*vote, node, safeblocks) {
		return
	}

	// If we get here, it means we are the leader so add the vote to our map of
	// votes seen.
	AppendVoteMessage(voteseen, *vote)

	// Check if we’ve gathered votes from 2/3rds of the validators, weighted by stake.

	voteStake := ComputeStake((*voteseen)[Hash(vote.View, vote.BlockHash)], node.PubKeyToStake)
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
		CombinedViewBlockHashSignature: BLSCombinedSignature{[]byte("a"), []byte("a")},
	}

	// Construct the block
	block := Block{
		PreviousBlockHash: qc.BlockHash,
		ProposerPublicKey: *node.PubKey,
		Txns:              GenerateTxns(10),
		View:              node.CurView,
		QC:                qc,
		AggregateQC: AggregateQC{
			View:                               0,
			ValidatorTimeoutHighQC:             QuorumCertificate{},
			ValidatorTimeoutHighQCViews:        nil,
			ValidatorCombinedTimeoutSignatures: BLSCombinedSignature{[]byte("a"), []byte("a")},
		},
	}

	// Sign the block using the leader’s private key.
	block.ProposerSignature, _ = Sign(block.Hash(), *node.PrivKey)
	// Blast the block to everyone including yourself. This means we'll process
	// this block in handleBlockFromPeer, where we'll also update our highestQC and
	// advance to the next view. As such, there is no reason to
	// call ResetTimeoutAndAdvanceView() here.
	broadcast(block)
}

func broadcast(block Block) {

}

// /Needs to be redone.
// /Needs to be redone
func validateTimeout(timeout TimeoutMessage, node *Node) bool {
	// Make sure that the validator is registered.
	if !verifyValidatorPublicKey(timeout.ValidatorPublicKey, node.PubKeys) {
		return false
	}

	// Verify the HighQC in the timeout message
	if !validateQuorumCertificate(timeout.HighQC) {
		return false
	}

	// Verify the validator signature
	payload := Hash(timeout.View, timeout.HighQC.View)
	if !VerifySignature(payload, timeout.ValidatorPublicKey, timeout.PartialTimeoutViewSignature) {
		return false
	}

	return true
}

func AppendTimeoutMessage(timeoutsSeen *map[[32]byte]map[string]TimeoutMessage, timeout TimeoutMessage) {
	// Check if the outer key exists in the map
	innerMap, ok := (*timeoutsSeen)[Hash(timeout.View, timeout.HighQC.BlockHash)]
	if !ok {
		// Initialize the inner map if it doesn't exist
		innerMap = make(map[string]TimeoutMessage)
		(*timeoutsSeen)[Hash(timeout.View, timeout.HighQC.BlockHash)] = innerMap
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
func GetTimeouthighQcViews(timeoutSeen map[string]TimeoutMessage) []uint64 {
	views := []uint64{}

	for _, timeout := range timeoutSeen {
		views = append(views, timeout.HighQC.View)
	}

	return views
}

// The handleTimeoutMessageFromPeer is called whenever we receive a timeout
// from a peer.
func handleTimeoutMessageFromPeer(timeoutMsg TimeoutMessage, node *Node, timeoutseen *map[[32]byte]map[string]TimeoutMessage) {
	// If we're not the leader, ignore all timeout messages.
	if !node.AmIaLeader(timeoutMsg.View) {
		return
	}

	// Make sure that the timeoutMsg is for the most recent view and validate all of
	// its signatures, including those for its HighQC. We also run a check to make
	// sure we didn’t already receive a timeout or another vote from this peer.
	if !validateTimeout(timeoutMsg, node) {
		return
	}

	// If we get here, it means we are the leader so add the timeoutMsg to our
	// map of timeouts seen.
	AppendTimeoutMessage(timeoutseen, timeoutMsg)
	// Check if we’ve gathered timeouts from 2/3rds of the validators, weighted
	// by stake.
	timeoutStake := ComputeStake((*timeoutseen)[Hash(timeoutMsg.View, timeoutMsg.HighQC.View)], node.PubKeyToStake)

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
	highQC := GetHighestViewHighQC((*timeoutseen)[Hash(timeoutMsg.View, timeoutMsg.HighQC.View)])
	views := GetTimeouthighQcViews((*timeoutseen)[Hash(timeoutMsg.View, timeoutMsg.HighQC.View)])
	//highQC, timeoutHighQCViews, timeoutHighQCCombinedSigs := FormatTimeoutQCs(timeoutsSeenMap)
	// Construct the AggregateQC for this view.
	aggregateQC := AggregateQC{
		View:                               timeoutMsg.View,
		ValidatorTimeoutHighQC:             highQC,
		ValidatorTimeoutHighQCViews:        views,
		ValidatorCombinedTimeoutSignatures: BLSCombinedSignature{[]byte("a"), []byte("a")},
	}

	// Construct the block and include the aggregateQC.
	block := Block{
		PreviousBlockHash: highQC.BlockHash,
		ProposerPublicKey: *node.PubKey,
		Txns:              GenerateTxns(10),
		View:              node.CurView,
		// Setting the QC is technically redundant when we have an AggregateQC but
		// we set it anyway for convenience.
		QC:          highQC,
		AggregateQC: aggregateQC,
	}

	// Sign the block using the leader’s private key.
	block.ProposerSignature, _ = Sign(block.Hash(), *node.PrivKey)
	// Blast the block to everyone including yourself. This means we'll process
	// this block in handleBlockFromPeer, where we'll also update our highestQC and
	// advance to the next view.
	broadcast(block)
}

// This is the node's main message and event handling loop. We continuously loop,
// incrementing the view with each round.
////*
//func StartConsensus() {
//	// We run an infinite loop, and process each message from our peers as it
//	// comes in. Note that the timeout is also something we might process as
//	// part of this main loop. If you are unfamiliar with the concept of a "select"
//	// statement, we recommend referencing Go's implementation here:
//	// - https://golangdocs.com/select-statement-in-golang
//	for {
//		select {
//		case messageFromPeer := <-networkChannel.WaitForMessage():
//			if messageFromPeer.MessageType() == BlockMessageType {
//				handleBlockFromPeer(messageFromPeer)
//
//			} else if messageFromPeer.MessageType() == VoteMessageType {
//				handleVoteMessageFromPeer(messageFromPeer)
//
//			} else if messageFromPeer.MessageType() == TimeoutMessageType {
//				handleTimeoutMessageFromPeer(messageFromPeer)
//
//			}
//		case <-WaitForTimeout():
//			// WaitForTimeout() is a function that will emit a value
//			// whenever a timeout is triggered, causing us to enter this part
//			// of the code. It can be assumed that calling
//			// ResetTimeout(timeoutValue) will cause WaitForTimeout() to emit
//			// a value after timeoutValue seconds have elapsed (ignoring all
//			// previous calls to ResetTimeout()).
//
//			// Construct the timeout message
//			timeoutMsg := TimeoutMessage{
//				ValidatorPublicKey:          myPublicKey,
//				TimeoutView:                 currentView,
//				HighQC:                      highestQC,
//				PartialTimeoutViewSignature: Sign(Hash(currentView, highestQC.View), myPrivateKey),
//			}
//
//			// Send the timeout message and send it to the next leader .
//			Send(timeoutMsg, computeLeader(currentView+1))
//
//			// We use exponential backoff for timeouts in this reference
//			// implementation.
//			ResetTimeoutAndAdvanceView(2 * timeoutSeconds)
//		case <-WaitForQuitSignal():
//			Exit()
//		}
//	}
//}
//*/
