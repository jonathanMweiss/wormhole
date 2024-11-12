package tss

import (
	"time"

	tsscommv1 "github.com/certusone/wormhole/node/pkg/proto/tsscomm/v1"
	"github.com/certusone/wormhole/node/pkg/tss/internal"
	"github.com/wormhole-foundation/wormhole/sdk/vaa"
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
	digest   *party.Digest       // nil if not seen yet.
	trackids map[trackidStr]bool // there might be multiple trackids for a single digest (due to multiple faults).
	chain    vaa.ChainID         // blockchain the message relates to (e.g. Ethereum, Solana, etc).

	approvedToSign bool

	signingComittee []*tss.PartyID // without faults.

	sawProtocolMessagesFrom map[strPartyId]bool // TODO.

	alertTime time.Time

	beginTime time.Time // used to do cleanups.
}

// GetEndTime is in capital to support the HasTTl interface.
func (s *signatureState) GetEndTime() time.Time {
	return s.alertTime
}

// Describes a specfic party's data in terms of fault tolerance.
type ftPartyData struct {
	timeToRevive       map[vaa.ChainID]time.Time // the time this party is expected to come back and be part of the protocol again.
	sigsUnderThisParty map[trackidStr]*signatureState
}

type ftTracker struct {
	sigAlerts internal.Ttlheap[*signatureState]
	sigsState map[trackidStr]*signatureState
	// for starters, we assume any fault is on all chains.
	membersData map[strPartyId]ftPartyData
	// reviveTimer   internal.Ttlheap[TODO:] // used to tell when someone can join the protocol again
}

// a single threaded env, that inspects incoming signatures request, message deliveries etc.
func (t *Engine) ftTracker() {
	f := &ftTracker{
		sigAlerts:   internal.NewTtlHeap[*signatureState](),
		sigsState:   make(map[trackidStr]*signatureState),
		membersData: make(map[strPartyId]ftPartyData),
	}

	for _, pid := range t.GuardianStorage.Guardians {
		strPid := strPartyId(partyIdToString(pid))
		f.membersData[strPid] = ftPartyData{
			timeToRevive:       map[vaa.ChainID]time.Time{},
			sigsUnderThisParty: map[trackidStr]*signatureState{},
		}
	}

	for {
		select {
		case <-t.ctx.Done():
			return
		case cmd := <-t.ftChans.tellCmd:
			f.applyCommand(t, cmd)
		case <-f.sigAlerts.WaitOnTimer():
			f.inspectAlertHeapsTop(t)
		}
	}
}

func (f *ftTracker) applyCommand(t *Engine, cmd isFtTrackerCmd) {
	switch c := cmd.(type) {
	case *signCommand:
		f.applySignCommand(t, c)
	case *deliveryCommand:
		f.applyDeliveryCommand(t, c)
	default:
		t.logger.Error("received unknown command type", zap.Any("cmd", cmd))
	}
}

func (f *ftTracker) applySignCommand(t *Engine, cmd *signCommand) {
	sigState, ok := f.sigsState[trackidStr(cmd.SigningInfo.TrackingID[:])]
	// TODO: Think how to handle all incoming trackid which are tied specifically to this digest.
	if !ok {
		sigState = &signatureState{
			digest:   nil,
			trackids: map[trackidStr]bool{},
			chain:    cmd.ChainID,

			signingComittee:         []*tss.PartyID{},
			sawProtocolMessagesFrom: map[strPartyId]bool{},
			alertTime:               time.Time{},
			beginTime:               time.Now(),
		}

		f.sigsState[trackidStr(cmd.Digest[:])] = sigState
	}

	sigState.approvedToSign = true

	cpy := party.Digest{}
	copy(cpy[:], cmd.Digest[:])
	sigState.digest = &cpy

	sigState.trackids[trackidStr(cmd.Digest[:])] = true
	sigState.trackids[trackidStr(cmd.SigningInfo.TrackingID)] = true

	sigState.chain = cmd.ChainID

	sigInfo := cmd.SigningInfo

	// check if we need to ammend the committee due to known faulties.
	faultiesInCurrentComittee := []*tss.PartyID{}
	for _, pid := range cmd.SigningInfo.SigningCommittee {
		m := f.membersData[strPartyId(partyIdToString(pid))]
		if m.timeToRevive[cmd.ChainID].After(time.Now()) { // TODO: see how to support overlapping case.
			faultiesInCurrentComittee = append(faultiesInCurrentComittee, pid)
		}
	}

	if len(faultiesInCurrentComittee) >= 0 {
		// todo: ensure that we remove this sig from responsibility of the faulties (in case they already started signing).
		newSigningInfo, err := t.fp.RemovePariticipantsFromSigning(cmd.Digest, faultiesInCurrentComittee)
		if err != nil {
			// TODO: should we inform error and tell others to stop relying on this guardian?
			panic("not implemented yet")
		}

		sigInfo = &newSigningInfo.NewSigningInfo
	}

	// store for each party the sigs it is responsible for.
	// thus on failure, we can find what sigs they should be removed from.
	for _, pid := range sigInfo.SigningCommittee {
		strPid := strPartyId(partyIdToString(pid))
		f.membersData[strPid].sigsUnderThisParty[trackidStr(cmd.SigningInfo.TrackingID[:])] = sigState
	}
}

func (f *ftTracker) applyDeliveryCommand(t *Engine, cmd *deliveryCommand) {
	// strTrackid := trackidStr(cmd.parsedMsg.WireMsg().TrackingID)
	// sigState, ok := f.sigsState[strTrackid]
	// if !ok {
	// 	sigState = &signatureState{
	// 		digest:                  nil, // unknown for now. TODO: consider adding to the message fields.
	// 		trackids:                map[trackidStr]bool{},
	// 		chain:                   -1, // unknown for now. (TODO: add fields to tss message to find the chain out)
	// 		approvedToSign:          false,
	// 		signingComittee:         []*tss.PartyID{}, // unknown for now.
	// 		sawProtocolMessagesFrom: map[strPartyId]bool{},
	// 		alertTime:               time.Now().Add(t.GuardianStorage.MaxSigStartWaitTime),
	// 		beginTime:               time.Now(),
	// 	}
	// 	f.sigsState[strTrackid] = sigState
	// }

	// sigState.trackids[strTrackid] = true

	// sigState.sawProtocolMessagesFrom[strPartyId(partyIdToString(cmd.from))] = true

	// // sigState.

}

func (f *ftTracker) inspectAlertHeapsTop(t *Engine) {
	sigState := f.sigAlerts.Dequeue()

	if sigState.approvedToSign {
		return
	}

	// At least one honest guardian saw the message, but I didn't (I'm probablt behined the network).
	if len(sigState.sawProtocolMessagesFrom) >= t.GuardianStorage.getMaxExpectedFaults()+1 {
		intoChannelOrDone(t.ctx, t.ftChans.tellProblem, Problem{
			idWithIssue:        partyIdToProto(t.Self),
			blockchainID:       sigState.chain,
			relenquishTime:     time.Now(),
			relenquishDuration: time.Minute * 10,
			signature:          []byte{}, // TODO
		})

		return
	}

	// haven't seen the message, but not behind the network (yet).
	// increasing timeout for this signature.
	sigState.alertTime = time.Now().Add(t.MaxSigStartWaitTime / 2) // TODO: what should be the value here?
	f.sigAlerts.Enqueue(sigState)
}
