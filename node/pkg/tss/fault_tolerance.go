package tss

import (
	"encoding/binary"
	"time"

	tsscommv1 "github.com/certusone/wormhole/node/pkg/proto/tsscomm/v1"
	"github.com/certusone/wormhole/node/pkg/tss/internal"
	"github.com/wormhole-foundation/wormhole/sdk/vaa"
	"github.com/yossigi/tss-lib/v2/common"
	"github.com/yossigi/tss-lib/v2/ecdsa/party"
	"github.com/yossigi/tss-lib/v2/tss"
	"go.uber.org/zap"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Fault tolerance:
// We adopt a straightforward approach to handle honest-but-missing-current-blocks
// failures (for availability reasons only, we assume honest but delayed behavior: nodes
// that haven’t upgraded their binaries to match the most recent code may
// not receive new blocks or transactions):
// A node that witness f+1 other nodes signing a digest that it hasn’t seen yet
// will assume it isn't up-to-date and will alert all other guardians (via reliable-broadcast protocol)
// and then stop signing temporarily.
//
// The logic behind this assumption is as follows:
// Since I observed that f+1 joined the protocol to sign, I must have at least one honest server
// who has seen the block and the signature, but I haven’t (after x seconds).
// This implies that I am delayed, and I should temporarily remove myself from the committees for some time.
//
//
// ft Process: each guardian keeps track of the digest, signatures and trackingIDs it saw using the
// ftTracker and its goroutine. The ftTracker receives ftCommands from the Engine and update its state
// according to these commands. It will output a problem message to the other guardians if it detects
// that it is behind the network.
// below is the ftCommand interface and the commands that implement it.

// ftCommand represents commands that reach the ftTracker.
// to become ftCommand, the struct must implement the apply(*Engine, *ftTracker) method.
//
// the commands include signCommand, deliveryCommand, getInactiveGuardiansCommand, and parsedProblem.
//   - signCommand is used to inform the ftTracker that a guardian saw a digest, and what related information
//     it has about the digest.
//   - deliveryCommand is used to inform the ftTracker that a guardian saw a message and forwarded it
//     to the fullParty.
//   - getInactiveGuardiansCommand is used to know which guardians aren't to be used in the protocol for
//     specific chainID.
//   - parsedProblem is used to deliver a problem message from another
//     guardian (after it was accepted by the reliable-broadcast protocol).
type ftCommand interface {
	apply(*Engine, *ftTracker)
}

type trackidStr string

type signCommand struct {
	SigningInfo *party.SigningInfo
}

// supporting the ftCmd interface
type deliveryCommand struct {
	parsedMsg tss.Message
	from      *tss.PartyID
}

type SigEndCommand struct {
	// TODO: don't forget to remove and release resources, and free memory from the chainData of a sig.
	*common.TrackingID
}

type reportProblemCommand struct {
	*parsedProblem
}

type inactives struct {
	partyIDs []*tss.PartyID

	downtimeEnding []*tss.PartyID
}

func (i *inactives) getFaultiesWithout(pid *tss.PartyID) []*tss.PartyID {
	if pid == nil {
		return i.partyIDs
	}

	if len(i.partyIDs) == 0 {
		return i.partyIDs
	}

	faulties := make([]*tss.PartyID, 0, len(i.partyIDs)-1)
	for _, p := range i.partyIDs {
		if equalPartyIds(p, pid) {
			continue
		}

		faulties = append(faulties, p)
	}

	return faulties
}

// Used to know which guardians aren't to be used in the protocol for specific chainID.
type getInactiveGuardiansCommand struct {
	ChainID vaa.ChainID
	reply   chan inactives
}

func (g *getInactiveGuardiansCommand) ftCmd() {}

type tackingIDContext struct {
	sawProtocolMessagesFrom map[strPartyId]bool
}

// the signatureState struct is used to keep track of a signature.
// the same struct is held by two different data structures:
//  1. a map so we can access and update the sigState easily.
//  2. a timedHeap that orders the signatures by the time they should be checked.
//     once the timedHeap timer expires we inspect the top (sigState) and decide whether we should report
//     a problem to the other guardians, or we should increase the timeout for this signature.
type signatureState struct {
	chain vaa.ChainID // blockchain the message relates to (e.g. Ethereum, Solana, etc).

	digest party.Digest
	// States whether the guardian saw the digest and forwarded it to the engine to be signed by TSS.
	approvedToSign bool

	// each trackingId is a unique attempt to sign a message.
	// Once one of the trackidStr saw f+1 guardians and we haven't seent the digest yet, we can assume
	// we are behind the network and we should inform the others.
	trackidContext map[trackidStr]*tackingIDContext

	alertTime time.Time

	beginTime time.Time // used to do cleanups.
}

// GetEndTime is in capital to support the HasTTl interface.
func (s *signatureState) GetEndTime() time.Time {
	return s.alertTime
}

type endDownTimeAlert struct {
	partyID   *tss.PartyID
	chain     vaa.ChainID
	alertTime time.Time
}

func (e *endDownTimeAlert) GetEndTime() time.Time {
	return e.alertTime
}

type sigStateKey party.Digest

type ftChainContext struct {
	timeToRevive                time.Time                       // the time this party is expected to come back and be part of the protocol again.
	liveSigsWaitingForThisParty map[sigStateKey]*signatureState // sigs that once the revive time expire should be retried.
}

// Describes a specfic party's data in terms of fault tolerance.
type ftParty struct {
	partyID        *tss.PartyID
	ftChainContext map[vaa.ChainID]*ftChainContext
}

type ftTracker struct {
	sigAlerts      internal.Ttlheap[*signatureState]
	sigsState      map[sigStateKey]*signatureState // TODO: sigState should include the chainID too, otherwise we might have two digest with  two differet chainIDs
	chainIdsToSigs map[vaa.ChainID]map[sigStateKey]*signatureState

	// for starters, we assume any fault is on all chains.
	membersData    map[strPartyId]*ftParty
	downtimeAlerts internal.Ttlheap[*endDownTimeAlert]
}

func newChainContext() *ftChainContext {
	return &ftChainContext{
		// ensuring the first time we see this party, we don't assume it's down.
		timeToRevive: time.Now().Add(-maxHeartbeatInterval),

		liveSigsWaitingForThisParty: map[sigStateKey]*signatureState{},
	}
}

// a single threaded env, that inspects incoming signatures request, message deliveries etc.
func (t *Engine) ftTracker() {
	f := &ftTracker{
		sigAlerts:      internal.NewTtlHeap[*signatureState](),
		sigsState:      make(map[sigStateKey]*signatureState),
		membersData:    make(map[strPartyId]*ftParty),
		downtimeAlerts: internal.NewTtlHeap[*endDownTimeAlert](),
	}

	for _, pid := range t.GuardianStorage.Guardians {
		strPid := strPartyId(partyIdToString(pid))
		f.membersData[strPid] = &ftParty{
			partyID:        pid,
			ftChainContext: map[vaa.ChainID]*ftChainContext{},
		}
	}

	maxttl := t.GuardianStorage.maxSignerTTL()

	ticker := time.NewTicker(maxttl)
	defer ticker.Stop()

	for {
		select {
		case <-t.ctx.Done():
			return

		case cmd := <-t.ftCommandChan:
			cmd.apply(t, f)

		case <-f.sigAlerts.WaitOnTimer():
			f.inspectAlertHeapsTop(t)

		case <-f.downtimeAlerts.WaitOnTimer():
			f.inspectDowntimeAlertHeapsTop(t)

		case <-ticker.C:
			f.cleanup(maxttl)
		}
	}
}

func (f *ftTracker) cleanup(maxttl time.Duration) {
	now := time.Now()

	for _, sigState := range f.sigsState {
		if now.Sub(sigState.beginTime) < maxttl {
			continue
		}

		f.remove(sigState)
	}
}

func (f *ftTracker) remove(sigState *signatureState) {
	for _, m := range f.membersData {
		delete(m.ftChainContext[sigState.chain].liveSigsWaitingForThisParty, sigStateKey(sigState.digest))
	}

	delete(f.sigsState, sigStateKey(sigState.digest))
}

func (cmd *reportProblemCommand) deteministicJitter(maxjitter time.Duration) time.Duration {
	bts, err := cmd.serialize()
	if err != nil {
		return 0
	}

	jitterBytes := hash(bts)
	nanoJitter := binary.BigEndian.Uint64(jitterBytes[:8])
	return (time.Duration(nanoJitter).Abs() % maxjitter).Abs()
}

func (cmd *reportProblemCommand) apply(t *Engine, f *ftTracker) {
	// at this point, we assume the parsedProblem's time is correct and the signature is valid.
	t.logger.Info("received a problem message from another guardian", zap.String("problem issuer", cmd.issuer.Id))

	pid := protoToPartyId(cmd.issuer)

	m := f.membersData[strPartyId(partyIdToString(pid))]

	jitter := cmd.deteministicJitter(t.GuardianStorage.MaxJitter)

	now := time.Now()
	// Adds some deterministic jitter to the time to revive, so parsedProblem messages that arrive at the same time
	// won't have the same revival time.
	reviveTime := now.Add(t.GuardianStorage.GuardianDownTime + jitter)

	chainID := vaa.ChainID(cmd.ChainID)
	chainData, ok := m.ftChainContext[chainID]
	if !ok {
		chainData = newChainContext()
		m.ftChainContext[chainID] = chainData
	}

	// we update the revival time only if the revival time had passed
	if now.After(chainData.timeToRevive) {
		chainData.timeToRevive = reviveTime
		f.downtimeAlerts.Enqueue(&endDownTimeAlert{
			partyID:   pid,
			chain:     chainID,
			alertTime: reviveTime,
		})
	}

	// if the problem is about this guardian, then there is no reason to retry the sigs since it won't
	// be part of the protocol.
	// we do let this guardian know that it is faulty and it's time so it can collect correct data
	// from signingInfo, which should be synchronised with the other guardians (if it attempts to sign later sigs).
	if equalPartyIds(pid, t.Self) {
		return
	}

	retryNow := chainData.liveSigsWaitingForThisParty
	chainData.liveSigsWaitingForThisParty = map[sigStateKey]*signatureState{} // clear the live sigs.

	go func() {
		for dgst := range retryNow {
			// TODO: maybe find something smarter to do here.
			t.BeginAsyncThresholdSigningProtocol(dgst[:], chainID)
		}
	}()
}

func (cmd *getInactiveGuardiansCommand) apply(t *Engine, f *ftTracker) {
	if cmd.reply == nil {
		t.logger.Error("reply channel is nil")
		return
	}

	reply := inactives{}

	for _, m := range f.membersData {
		chainData, ok := m.ftChainContext[cmd.ChainID]
		if !ok {
			chainData = newChainContext()
			m.ftChainContext[cmd.ChainID] = chainData

			continue // never seen before, so it's active.
		}

		diff := time.Until(chainData.timeToRevive)

		//  |revive_time - now| < synchronsingInterval, then its time to revive comes soon.
		if diff.Abs() < synchronsingInterval {
			reply.downtimeEnding = append(reply.downtimeEnding, m.partyID)
		}

		// if revive time is in the future, then the guardian is inactive.
		if diff > 0 {
			reply.partyIDs = append(reply.partyIDs, m.partyID)
		}
	}

	if err := intoChannelOrDone(t.ctx, cmd.reply, reply); err != nil {
		t.logger.Error("error on telling on inactive guardians on specific chain", zap.Error(err))
	}

	close(cmd.reply)
}

// used to update the state of the signature, ensuring alerts can be ignored.
func (cmd *signCommand) apply(t *Engine, f *ftTracker) {
	tid := cmd.SigningInfo.TrackingID
	if tid == nil {
		t.logger.Error("signCommand: tracking id is nil")
		return
	}

	dgst := party.Digest{}
	copy(dgst[:], tid.Digest[:])

	// TODO: Ensure the digest contains the auxilaryData. otherwise, there can be two signatures witth the same digest? I doubt it.
	state, ok := f.sigsState[sigStateKey(dgst)]
	if !ok {
		state = f.setNewSigState(tid, time.Now())
	}

	state.approvedToSign = true
	for _, pid := range cmd.SigningInfo.SigningCommittee {
		m, ok := f.membersData[strPartyId(partyIdToString(pid))]
		if !ok {
			t.logger.Error("signCommand: party not found in the members data")

			continue
		}

		chainData, ok := m.ftChainContext[state.chain]
		if !ok {
			chainData = newChainContext()
			m.ftChainContext[state.chain] = chainData
		}

		chainData.liveSigsWaitingForThisParty[sigStateKey(dgst)] = state
	}
}

func (cmd *deliveryCommand) apply(t *Engine, f *ftTracker) {
	wmsg := cmd.parsedMsg.WireMsg()
	if wmsg == nil {
		t.logger.Error("deliveryCommand: wire message is nil")
		return
	}

	tid := wmsg.GetTrackingID()
	if tid == nil {
		t.logger.Error("deliveryCommand: tracking id is nil")
		return
	}

	dgst := party.Digest{}
	copy(dgst[:], tid.GetDigest())

	state, ok := f.sigsState[sigStateKey(dgst)]
	if !ok {
		alertTime := time.Now().Add(t.GuardianStorage.MaxSigStartWaitTime)
		state = f.setNewSigState(tid, alertTime)

		// Since this is a delivery and not a sign command, we add this to the alert heap.
		f.sigAlerts.Enqueue(state)
	}

	tidData, ok := state.trackidContext[trackidStr(tid.ToString())]
	if !ok {
		tidData = &tackingIDContext{
			sawProtocolMessagesFrom: map[strPartyId]bool{},
		}

		state.trackidContext[trackidStr(tid.ToString())] = tidData
	}

	tidData.sawProtocolMessagesFrom[strPartyId(partyIdToString(cmd.from))] = true
}

func (f *ftTracker) setNewSigState(tid *common.TrackingID, alertTime time.Time) *signatureState {
	dgst := party.Digest{}
	copy(dgst[:], tid.Digest)

	state := &signatureState{
		chain:          extractChainIDFromTrackingID(tid),
		digest:         dgst,
		approvedToSign: false,
		trackidContext: map[trackidStr]*tackingIDContext{},
		alertTime:      alertTime,
		beginTime:      time.Now(),
	}

	f.sigsState[sigStateKey(dgst)] = state

	return state
}
func (f *ftTracker) inspectAlertHeapsTop(t *Engine) {
	sigState := f.sigAlerts.Dequeue()

	if sigState.approvedToSign {
		return
	}

	if _, exists := f.sigsState[sigStateKey(sigState.digest)]; !exists {
		// sig is removed (either old, or finished signing), and we don't need to do anything.
		return
	}

	// At least one honest guardian saw the message, but I didn't (I'm probablt behined the network).
	if sigState.maxGuardianVotes() >= t.GuardianStorage.getMaxExpectedFaults()+1 {
		t.reportProblem(sigState.chain)

		return
	}

	// haven't seen the message, but not behind the network (yet).
	// increasing timeout for this signature.
	sigState.alertTime = time.Now().Add(t.MaxSigStartWaitTime / 2) // TODO: what should be the value here?
	f.sigAlerts.Enqueue(sigState)
}

func (t *Engine) reportProblem(chain vaa.ChainID) {
	t.logger.Info("noticed i'm behind others and attemmpting to inform them",
		zap.String("chainID", chain.String()),
	)

	sm := &tsscommv1.SignedMessage{
		Content: &tsscommv1.SignedMessage_Problem{
			Problem: &tsscommv1.Problem{
				ChainID:     uint32(chain),
				Emitter:     0, // TODO
				IssuingTime: timestamppb.Now(),
			},
		},

		Sender:    partyIdToProto(t.Self),
		Signature: []byte{},
	}

	if err := t.sign(sm); err != nil {
		t.logger.Error("failed to report a problem to the other guardians", zap.Error(err))

		return
	}

	intoChannelOrDone[Sendable](t.ctx, t.messageOutChan, newEcho(sm, t.guardiansProtoIDs))
}

// get the maximal amount of guardians that saw the digest and started signing.
func (s *signatureState) maxGuardianVotes() int {
	max := 0
	for _, tidData := range s.trackidContext {
		if len(tidData.sawProtocolMessagesFrom) > max {
			max = len(tidData.sawProtocolMessagesFrom)
		}
	}

	return max
}

func (f *ftTracker) inspectDowntimeAlertHeapsTop(t *Engine) {
	// TODO: implement this.
	// downtimeEndAlert := f.downtimeAlerts.Dequeue()
	// need to go for each signature, and check

	panic("not implemented")
}
