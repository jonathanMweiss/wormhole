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

func (s *broadcaststate) updateState(f int, msg *tsscommv1.Echo) (shouldEcho bool, err error) {
	isMsgSrc := equalPartyIds(protoToPartyId(msg.Echoer), protoToPartyId(msg.Message.Sender))

	// checking outside of lock since s.messageDigest is read only after creation.
	if s.messageDigest != hashSignedMessage(msg.Message) {
		return false, fmt.Errorf("%w: %v", ErrEquivicatingGuardian, msg.Echoer)
	}

	s.mtx.Lock()
	defer s.mtx.Unlock()

	s.votes[voterId{id: msg.Echoer.Id, key: string(msg.Echoer.Key)}] = true // stores only validate
	if s.echoedAlready {
		return
	}

	if isMsgSrc {
		s.echoedAlready = true
		shouldEcho = true
		return
	}

	// at least one honest guardian heard this echo (meaning all honests will hear this message eventually).
	if len(s.votes) >= f+1 {
		s.echoedAlready = true
		shouldEcho = true
		return
	}

	return
}

func (st *GuardianStorage) getMaxExpectedFaults() int {
	// since threshold is 2/3 *f +1, f = (st.Threshold - 1) / 2
	// in our case st.Threshold is not inclusive, so we don't need to subtract 1.
	return (st.Threshold) / 2 // this is the floor of the result.
}

func (t *Engine) relbroadcastInspection(parsed tss.ParsedMessage, msg *tsscommv1.Echo) (shouldEcho bool, shouldDeliver bool, err error) {
	d, err := t.getMessageUUID(parsed)
	if err != nil {
		return false, false, err
	}

	t.mtx.Lock()
	state, ok := t.received[d]
	if !ok {
		if err := t.verifySignedMessage(msg.Message); err != nil {
			return false, false, err
		}

		state = &broadcaststate{
			timeReceived:     time.Now(),
			message:          msg.Message,
			messageDigest:    hashSignedMessage(msg.Message),
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

	allowedToBroadcast, err := state.updateState(f, msg)
	if err != nil {
		return false, false, err
	}

	if state.shouldDeliver(f) {
		return allowedToBroadcast, true, nil
	}

	return allowedToBroadcast, false, nil
}
