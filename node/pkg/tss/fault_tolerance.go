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
)

// Fault tolerance:
// We adopt a straightforward approach to handle “semi-omission” failures (for availability reasons only, we assume honest but delayed behavior: nodes that haven’t upgraded their binaries to match the most recent code may not receive new blocks or transactions):
// A node assumes that if f+1 begins signing, but it hasn’t received any new blocks or transactions yet, it will temporarily stop signing.
//
// The logic behind this assumption is as follows:
// Since I observed that f+1 joined the protocol to sign, I must have at least one honest server who has seen the block and the signature, but I haven’t.
// This implies that I am delayed, and I should temporarily remove myself from the committees for some time.

type trackidStr string
type isFtTrackerCmd interface {
	// TODO: consider applyCmd(*Engine, *ftTracker) instead of this.
	isCmd() // marker interface
}

type signCommand struct {
	Digest      party.Digest
	ChainID     vaa.ChainID
	SigningInfo *party.SigningInfo
}

// supporting the isFtTrackerCmd interface
func (s *signCommand) isCmd() {}

type sigDoneCommand struct {
	Digest  party.Digest
	trackId []byte
}

func (s *sigDoneCommand) isCmd() {}

type deliveryCommand struct {
	parsedMsg tss.Message
	from      *tss.PartyID
}

// supporting the isFtTrackerCmd interface
func (d *deliveryCommand) isCmd() {}

type inactives struct {
	partyIDs []*tss.PartyID
}

// Used to know which guardians aren't to be used in the protocol for specific chainID.
type getInactiveGuardiansCommand struct {
	ChainID vaa.ChainID
	reply   chan inactives
}

func (g *getInactiveGuardiansCommand) isCmd() {}

type ftChans struct {
	tellCmd chan isFtTrackerCmd
	//removeTrackID chan []byte//  TODO: make part of cmd: //  // the engine might request to clean trackIDs related to the reliable-broadcast.
	tellProblem chan Problem
}

type Problem struct {
	idWithIssue *tsscommv1.PartyId
	// hadntSeenTrackId []byte      // trackid
	blockchainID vaa.ChainID // what chain this problem is related to.

	relenquishTime     time.Time
	relenquishDuration time.Duration

	signature []byte

	// TODO: consider more fields.
	// digest
	// blockchain info
}

// this signature structs are held by two different data structures.
// 1. a map so we can access and update these easily.
// 2. a heap to keep track of the ttl of each signature.
//
// Once the timer of the heap pops, we check the state of the signature and decide what to do (change comitte members, etc).
type signatureState struct {
	chain vaa.ChainID // blockchain the message relates to (e.g. Ethereum, Solana, etc).

	approvedToSign bool

	// each trackingId is a unique attempt to sign a message.
	// Once one of the trackidStr saw f+1 guardians and we haven't seent the digest yet, we can assume
	// we are behind the network and we should inform the others.
	sawProtocolMessagesFrom map[trackidStr]map[strPartyId]bool

	alertTime time.Time

	beginTime time.Time // used to do cleanups.
}

// GetEndTime is in capital to support the HasTTl interface.
func (s *signatureState) GetEndTime() time.Time {
	return s.alertTime
}

// Describes a specfic party's data in terms of fault tolerance.
type ftPartyData struct {
	partyID            *tss.PartyID
	timeToRevive       map[vaa.ChainID]time.Time // the time this party is expected to come back and be part of the protocol again.
	sigsUnderThisParty map[party.Digest]*signatureState
}

type ftTracker struct {
	sigAlerts internal.Ttlheap[*signatureState]
	sigsState map[party.Digest]*signatureState
	// for starters, we assume any fault is on all chains.
	membersData map[strPartyId]ftPartyData
	// reviveTimer   internal.Ttlheap[TODO:] // used to tell when someone can join the protocol again
}

// a single threaded env, that inspects incoming signatures request, message deliveries etc.
func (t *Engine) ftTracker() {
	f := &ftTracker{
		sigAlerts:   internal.NewTtlHeap[*signatureState](),
		sigsState:   make(map[party.Digest]*signatureState),
		membersData: make(map[strPartyId]ftPartyData),
	}

	for _, pid := range t.GuardianStorage.Guardians {
		strPid := strPartyId(partyIdToString(pid))
		f.membersData[strPid] = ftPartyData{
			timeToRevive:       map[vaa.ChainID]time.Time{},
			sigsUnderThisParty: map[party.Digest]*signatureState{},
		}
	}

	for {
		select {
		case <-t.ctx.Done():
			return
		case cmd := <-t.ftChans.tellCmd:
			f.executeCommand(t, cmd)
		case <-f.sigAlerts.WaitOnTimer():
			f.inspectAlertHeapsTop(t)
		}
	}
}

func (f *ftTracker) executeCommand(t *Engine, cmd isFtTrackerCmd) {
	switch c := cmd.(type) {
	case *signCommand:
		f.executeSignCommand(t, c)
	case *deliveryCommand:
		f.executeDeliveryCommand(t, c)
	case *getInactiveGuardiansCommand:
		f.executeGetIncativeGuardiansCommand(t, c)
	default:
		t.logger.Error("received unknown command type", zap.Any("cmd", cmd))
	}
}

func (f *ftTracker) executeGetIncativeGuardiansCommand(t *Engine, cmd *getInactiveGuardiansCommand) {
	if cmd.reply == nil {
		t.logger.Error("reply channel is nil")
		return
	}

	reply := inactives{}
	for _, m := range f.membersData {
		t, ok := m.timeToRevive[cmd.ChainID]
		if ok && t.After(time.Now()) { // TODO: maybe add some buffer time here. + support more than one attemp
			reply.partyIDs = append(reply.partyIDs, m.partyID)
		}
	}

	intoChannelOrDone(t.ctx, cmd.reply, reply)
	close(cmd.reply)
}

// used to update the state of the signature, ensuring alerts can be ignored.
func (f *ftTracker) executeSignCommand(t *Engine, cmd *signCommand) {
	state, ok := f.sigsState[cmd.Digest]
	if !ok {
		state = &signatureState{
			sawProtocolMessagesFrom: map[trackidStr]map[strPartyId]bool{},
			alertTime:               time.Now(), // no alert time.
			beginTime:               time.Now(),
		}
		f.sigsState[cmd.Digest] = state
	}

	state.chain = cmd.ChainID
	state.approvedToSign = true
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
			chain:                   extractChainIDFromTrackingID(tid),
			approvedToSign:          false,
			sawProtocolMessagesFrom: map[trackidStr]map[strPartyId]bool{},
			alertTime:               time.Now().Add(t.GuardianStorage.MaxSigStartWaitTime),
			beginTime:               time.Now(),
		}
		f.sigsState[dgst] = state

		// Since this is a delivery and not a sign command, we add this to the alert heap.
		f.sigAlerts.Enqueue(state)
	}

	votes, ok := state.sawProtocolMessagesFrom[trackidStr(tid.ToString())]
	if !ok {
		votes = map[strPartyId]bool{}
		state.sawProtocolMessagesFrom[trackidStr(tid.ToString())] = votes
	}

	votes[strPartyId(partyIdToString(cmd.from))] = true
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
		problem := Problem{
			idWithIssue:        partyIdToProto(t.Self),
			blockchainID:       sigState.chain,
			relenquishTime:     time.Now(),
			relenquishDuration: time.Minute * 10,
			signature:          []byte{}, // TODO: must be signed.
			// perhaps loaded into echo and signed there...
		}

		t.logger.Warn("detected a possible fault", zap.Any("", problem))

		intoChannelOrDone(t.ctx, t.ftChans.tellProblem, problem)

		return
	}

	// haven't seen the message, but not behind the network (yet).
	// increasing timeout for this signature.
	sigState.alertTime = time.Now().Add(t.MaxSigStartWaitTime / 2) // TODO: what should be the value here?
	f.sigAlerts.Enqueue(sigState)
}

func (s *signatureState) maxGuardianVotes() int {
	max := 0
	for _, uniqueVoters := range s.sawProtocolMessagesFrom {
		if len(uniqueVoters) > max {
			max = len(uniqueVoters)
		}
	}

	return max
}
