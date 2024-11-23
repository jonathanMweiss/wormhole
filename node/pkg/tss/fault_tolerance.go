package tss

import (
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
// not receive new blocks or transactions): A node assumes that if f+1 begins signing,
//but it hasn’t received any new blocks or transactions yet, it will temporarily stop signing.
//
// The logic behind this assumption is as follows:
// Since I observed that f+1 joined the protocol to sign, I must have at least one honest server who has seen the block and the signature, but I haven’t.
// This implies that I am delayed, and I should temporarily remove myself from the committees for some time.

type trackidStr string
type ftCommand interface {
	// TODO: consider applyCmd(*Engine, *ftTracker) instead of this.
	ftCmd() // marker interface
}

type signCommand struct {
	SigningInfo *party.SigningInfo
}

// supporting the ftCmd interface
func (s *signCommand) ftCmd() {}

type deliveryCommand struct {
	parsedMsg tss.Message
	from      *tss.PartyID
}

type SigEndCommand struct {
	// TODO: don't forget to remove and release resources, and free memory from the chainData of a sig.
	*common.TrackingID
}

// supporting the ftCmd interface
func (d *deliveryCommand) ftCmd() {}

type inactives struct {
	partyIDs []*tss.PartyID

	downtimeEnding []*tss.PartyID
}

func (i *inactives) getFaultiesWithout(pid *tss.PartyID) []*tss.PartyID {
	if pid == nil {
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

type trackIDSigRelatedData struct {
	sawProtocolMessagesFrom map[strPartyId]bool
}

// this signature structs are held by two different data structures.
// 1. a map so we can access and update these easily.
// 2. a heap to keep track of the ttl of each signature.
//
// Once the timer of the heap pops, we check the state of the signature and decide what to do (change comitte members, etc).
type signatureState struct {
	chain vaa.ChainID // blockchain the message relates to (e.g. Ethereum, Solana, etc).

	// States whether the guardian saw the digest and forwarded it to the engine to be signed by TSS.
	approvedToSign bool

	// each trackingId is a unique attempt to sign a message.
	// Once one of the trackidStr saw f+1 guardians and we haven't seent the digest yet, we can assume
	// we are behind the network and we should inform the others.
	trackidRelatedData map[trackidStr]*trackIDSigRelatedData

	alertTime time.Time

	beginTime time.Time // used to do cleanups.
}

// GetEndTime is in capital to support the HasTTl interface.
func (s *signatureState) GetEndTime() time.Time {
	return s.alertTime
}

type ftChainData struct {
	timeToRevive time.Time // the time this party is expected to come back and be part of the protocol again.
	// sigs that once the revive time expire should be retried.
	retrySigs                   map[party.Digest]*signatureState
	liveSigsWaitingForThisParty map[party.Digest]*signatureState
}

// Describes a specfic party's data in terms of fault tolerance.
type ftParty struct {
	partyID     *tss.PartyID
	ftPartyData map[vaa.ChainID]*ftChainData
}

type ftTracker struct {
	sigAlerts internal.Ttlheap[*signatureState]
	sigsState map[party.Digest]*signatureState
	// for starters, we assume any fault is on all chains.
	membersData map[strPartyId]*ftParty
}

func newEmptyChainData() *ftChainData {
	return &ftChainData{
		timeToRevive:                time.Now(),
		retrySigs:                   map[party.Digest]*signatureState{},
		liveSigsWaitingForThisParty: map[party.Digest]*signatureState{},
	}
}

// a single threaded env, that inspects incoming signatures request, message deliveries etc.
func (t *Engine) ftTracker() {
	f := &ftTracker{
		sigAlerts:   internal.NewTtlHeap[*signatureState](),
		sigsState:   make(map[party.Digest]*signatureState),
		membersData: make(map[strPartyId]*ftParty),
	}

	for _, pid := range t.GuardianStorage.Guardians {
		strPid := strPartyId(partyIdToString(pid))
		f.membersData[strPid] = &ftParty{
			partyID:     pid,
			ftPartyData: map[vaa.ChainID]*ftChainData{},
		}
	}

	for {
		select {
		case <-t.ctx.Done():
			return

		case cmd := <-t.ftCommandChan:
			f.executeCommand(t, cmd)
		case <-f.sigAlerts.WaitOnTimer():
			f.inspectAlertHeapsTop(t)
		}
	}
}

func (f *ftTracker) executeCommand(t *Engine, cmd ftCommand) {
	switch c := cmd.(type) {
	case *signCommand:
		f.executeSignCommand(t, c)
	case *deliveryCommand:
		f.executeDeliveryCommand(t, c)
	case *getInactiveGuardiansCommand:
		f.executeGetIncativeGuardiansCommand(t, c)
	case *parsedProblem:
		f.executeParsedProblemCommand(t, c)
	default:
		t.logger.Error("received unknown command type", zap.Any("cmd", cmd))
	}
}

func (f *ftTracker) executeParsedProblemCommand(t *Engine, cmd *parsedProblem) {
	t.logger.Info("received a problem message from another guardian", zap.Any("problem issuer", cmd.issuer))

	pid := protoToPartyId(cmd.issuer)

	m := f.membersData[strPartyId(partyIdToString(pid))]

	reviveTime := time.Now().Add(t.GuardianStorage.GuardianSigningDownTime)
	chainID := vaa.ChainID(cmd.ChainID)

	chainData, ok := m.ftPartyData[chainID]
	if !ok {
		chainData = newEmptyChainData()
		m.ftPartyData[chainID] = chainData
	}

	// we update the revival time only if the revival time had passed
	if time.Now().After(chainData.timeToRevive) {
		chainData.timeToRevive = reviveTime
		// TODO: insert to some timed heap
	}

	if equalPartyIds(pid, t.Self) {
		return
	}

	retryNow := chainData.liveSigsWaitingForThisParty
	chainData.liveSigsWaitingForThisParty = map[party.Digest]*signatureState{} // clear the live sigs.

	go func() {
		for dgst := range retryNow {
			// TODO: maybe find something smarter to do here.
			t.BeginAsyncThresholdSigningProtocol(dgst[:])
		}
	}()
}

func (f *ftTracker) executeGetIncativeGuardiansCommand(t *Engine, cmd *getInactiveGuardiansCommand) {
	if cmd.reply == nil {
		t.logger.Error("reply channel is nil")
		return
	}

	reply := inactives{}
	for _, m := range f.membersData {
		chainData, ok := m.ftPartyData[cmd.ChainID]
		if !ok {
			chainData = newEmptyChainData()
			m.ftPartyData[cmd.ChainID] = chainData
		}

		if chainData.timeToRevive.After(time.Now()) {
			reply.partyIDs = append(reply.partyIDs, m.partyID)
		}

		if chainData.timeToRevive.Before(time.Now().Add(time.Second * 10)) {
			reply.downtimeEnding = append(reply.downtimeEnding, m.partyID)
		}
	}

	if err := intoChannelOrDone(t.ctx, cmd.reply, reply); err != nil {
		t.logger.Error("error on telling on inactive guardians on specific chain", zap.Error(err))
	}

	close(cmd.reply)
}

// used to update the state of the signature, ensuring alerts can be ignored.
func (f *ftTracker) executeSignCommand(t *Engine, cmd *signCommand) {
	tid := cmd.SigningInfo.TrackingID
	if tid == nil {
		t.logger.Error("signCommand: tracking id is nil")
		return
	}

	dgst := party.Digest{}
	copy(dgst[:], tid.Digest[:])

	state, ok := f.sigsState[dgst]
	if !ok {
		state = &signatureState{
			chain: extractChainIDFromTrackingID(tid),

			trackidRelatedData: map[trackidStr]*trackIDSigRelatedData{},
			alertTime:          time.Now(),
			beginTime:          time.Now(),
		}
		f.sigsState[dgst] = state
	}

	state.approvedToSign = true
	for _, pid := range cmd.SigningInfo.SigningCommittee {
		m, ok := f.membersData[strPartyId(partyIdToString(pid))]
		if !ok {
			t.logger.Error("signCommand: party not found in the members data")

			continue
		}

		chainData, ok := m.ftPartyData[state.chain]
		if !ok {
			chainData = newEmptyChainData()
			m.ftPartyData[state.chain] = chainData
		}

		chainData.liveSigsWaitingForThisParty[dgst] = state
	}
}

func (f *ftTracker) executeDeliveryCommand(t *Engine, cmd *deliveryCommand) {
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

	state, ok := f.sigsState[dgst]
	if !ok {
		// create a sig state.
		state = &signatureState{
			chain:              extractChainIDFromTrackingID(tid),
			approvedToSign:     false,
			trackidRelatedData: map[trackidStr]*trackIDSigRelatedData{},
			alertTime:          time.Now().Add(t.GuardianStorage.MaxSigStartWaitTime),
			beginTime:          time.Now(),
		}
		f.sigsState[dgst] = state

		// Since this is a delivery and not a sign command, we add this to the alert heap.
		f.sigAlerts.Enqueue(state)
	}

	tidData, ok := state.trackidRelatedData[trackidStr(tid.ToString())]
	if !ok {
		tidData = &trackIDSigRelatedData{
			sawProtocolMessagesFrom: map[strPartyId]bool{},
		}

		state.trackidRelatedData[trackidStr(tid.ToString())] = tidData
	}

	tidData.sawProtocolMessagesFrom[strPartyId(partyIdToString(cmd.from))] = true
}

func extractChainIDFromTrackingID(tid *common.TrackingID) vaa.ChainID {
	return 0 // TODO.
}

func (f *ftTracker) inspectAlertHeapsTop(t *Engine) {
	sigState := f.sigAlerts.Dequeue()

	if sigState.approvedToSign {
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
	for _, tidData := range s.trackidRelatedData {
		if len(tidData.sawProtocolMessagesFrom) > max {
			max = len(tidData.sawProtocolMessagesFrom)
		}
	}

	return max
}
