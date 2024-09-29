package tss

import (
	"fmt"
	"sync"
	"time"

	tsscommv1 "github.com/certusone/wormhole/node/pkg/proto/tsscomm/v1"
	"github.com/yossigi/tss-lib/v2/tss"
)

// The following code follows Bracha's reliable broadcast algorithm.

// voterId is comprised from the id and key of the signer, should match the guardians (in GuardianStorage) id and key.
type voterId struct {
	id  string
	key string
}

type broadcaststate struct {
	// The following three fields should not be changed after creation of broadcaststate:
	timeReceived  time.Time
	message       *tsscommv1.SignedMessage
	messageDigest digest

	votes map[voterId]bool
	// if set to true: don't echo again, even if received from original sender.
	echoedAlready bool
	// if set to true: don't deliver again.
	alreadyDelivered bool

	mtx *sync.Mutex
}

func (s *broadcaststate) shouldDeliver(f int) bool {
	s.mtx.Lock()
	defer s.mtx.Unlock()

	if s.alreadyDelivered {
		return false
	}

	if len(s.votes) < f*2+1 {
		return false
	}

	s.alreadyDelivered = true

	return true
}

var ErrEquivicatingGuardian = fmt.Errorf("equivication, guardian sent two different messages for the same round and session")

func (s *broadcaststate) updateState(f int, msg *tsscommv1.SignedMessage, echoer *tsscommv1.PartyId) (shouldEcho bool, err error) {
	isMsgSrc := equalPartyIds(protoToPartyId(echoer), protoToPartyId(msg.Sender))

	// checking outside of lock since s.messageDigest is read only after creation.
	if s.messageDigest != hashSignedMessage(msg) {
		return false, fmt.Errorf("%w: %v", ErrEquivicatingGuardian, echoer)
	}

	s.mtx.Lock()
	defer s.mtx.Unlock()

	s.votes[voterId{id: echoer.Id, key: string(echoer.Key)}] = true // stores only validate
	if s.echoedAlready {
		return shouldEcho, err
	}

	if isMsgSrc {
		s.echoedAlready = true
		shouldEcho = true

		return shouldEcho, err
	}

	// at least one honest guardian heard this echo (meaning all honests will hear this message eventually).
	if len(s.votes) >= f+1 {
		s.echoedAlready = true
		shouldEcho = true

		return shouldEcho, err
	}

	return shouldEcho, err
}

func (st *GuardianStorage) getMaxExpectedFaults() int {
	// since threshold is 2/3 *f +1, f = (st.Threshold - 1) / 2
	// in our case st.Threshold is not inclusive, so we don't need to subtract 1.
	return (st.Threshold) / 2 // this is the floor of the result.
}

func (t *Engine) relbroadcastInspection(parsed tss.ParsedMessage, msg Incoming) (shouldEcho bool, shouldDeliver bool, err error) {
	d, err := t.getMessageUUID(parsed)
	if err != nil {
		return false, false, err
	}

	if echo := msg.toEcho(); echo == nil || echo.Message == nil {
		return false, false, fmt.Errorf("expected echo, received nil")
	}

	signed := msg.toEcho().Message
	echoer := msg.GetSource()

	t.mtx.Lock()
	state, ok := t.received[d]

	if !ok {
		if err := t.verifySignedMessage(signed); err != nil {
			return false, false, err
		}

		state = &broadcaststate{
			timeReceived:     time.Now(),
			message:          signed,
			messageDigest:    hashSignedMessage(signed),
			votes:            make(map[voterId]bool),
			echoedAlready:    false,
			alreadyDelivered: false,
			mtx:              &sync.Mutex{},
		}

		t.received[d] = state
	}

	t.mtx.Unlock()

	// If we weren't using TLS - at this point we would have to verify the signature of the message.

	f := t.GuardianStorage.getMaxExpectedFaults()

	allowedToBroadcast, err := state.updateState(f, signed, echoer)
	if err != nil {
		return false, false, err
	}

	if state.shouldDeliver(f) {
		return allowedToBroadcast, true, nil
	}

	return allowedToBroadcast, false, nil
}
