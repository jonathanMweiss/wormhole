package tss

import (
	"sync"
	"time"

	tsscommv1 "github.com/certusone/wormhole/node/pkg/proto/tsscomm/v1"
	"github.com/certusone/wormhole/node/pkg/tss/internal"
	"github.com/yossigi/tss-lib/v2/ecdsa/party"
	"github.com/yossigi/tss-lib/v2/tss"
)

type trackidStr string
type Problem struct {
	idWithIssue *tsscommv1.PartyId
	hadntSeen   []byte // trackid
}

// Fault tolerance:
// We adopt a straightforward approach to handle “semi-omission” failures (for availability reasons only, we assume honest but delayed behavior: nodes that haven’t upgraded their binaries to match the most recent code may not receive new blocks or transactions):
// A node assumes that if f+1 begins signing, but it hasn’t received any new blocks or transactions yet, it will temporarily stop signing.
//
// The logic behind this assumption is as follows:
// Since I observed that f+1 joined the protocol to sign, I must have at least one honest server who has seen the block and the signature, but I haven’t.
// This implies that I am delayed, and I should temporarily remove myself from the committees for some time.

// this signature structs are held by two different data structures.
// 1. a map so we can access and update these easily.
// 2. a heap to keep track of the ttl of each signature.
//
// Once the timer of the heap pops, we check the state of the signature and decide what to do (change comitte members, etc).
type signatureState struct {
	mtx     sync.Mutex
	digest  party.Digest
	trackid []byte

	startedSigning bool

	signingCommittee []*tss.PartyID
	failingServers   []*tss.PartyID // Any delivery failure witnessed is collected here.

	// the following field is updated before feeding the FP with this value.
	sawUnicastsFrom []*tss.PartyID // TODO.

	EndTime time.Time // set x seconds, once timer pops, check if advanced to next round.
	// if something wasn't delivered from some guardian -> Remove this guardian from committee.
	// For each round advanced: add x seconds to ttl.
}

// GetEndTime is in capital to support the HasTTl interface.
func (s *signatureState) GetEndTime() time.Time {
	s.mtx.Lock()
	endtime := s.EndTime
	s.mtx.Unlock()

	return endtime
}

// a single threaded env, that inspects incoming signatures request, message deliveries etc.
func (t *Engine) tracker() {
	var alertHeap = internal.NewTtlHeap[*signatureState]()
	// var sigsStates = map[trackidStr]*signatureState{}

	for {
		select {
		case <-t.ctx.Done():
			return

		// case tsmsg := <-t.deliveryTrackChan:
		// 	// TODO:
		case <-alertHeap.WaitOnTimer():
			sigState := alertHeap.Dequeue()

			sigState.mtx.Lock()
			if sigState.startedSigning {
				sigState.mtx.Unlock()
				continue
			}

			// At least one honest guardian saw the message, but I didn't (I'm probablt behined the network).
			if len(sigState.sawUnicastsFrom) >= t.GuardianStorage.getMaxExpectedFaults()+1 {
				sigState.mtx.Unlock()
				t.tellProblem <- Problem{
					idWithIssue: partyIdToProto(t.Self),
					hadntSeen:   sigState.trackid,
				}

				continue
			}

			// I haven't seen the message, but I'm not certain I'm behind the network.
			// increasing timeout for this signature.
			sigState.EndTime = time.Now().Add(time.Second * 5)
			alertHeap.Enqueue(sigState)
			sigState.mtx.Unlock()
		}
	}
}
