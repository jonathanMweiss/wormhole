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
type voterId string

type broadcaststate struct {
	// The following three fields should not be changed after creation of broadcaststate:
	timeReceived  time.Time
	messageDigest *digest
	trackingId    []byte

	// voters mapping between voter and the messageDigest they voted for (claimed as seen).
	votes map[voterId]digest

	// if set to true: don't echo again, even if received from original sender.
	echoedAlready bool
	// if set to true: don't deliver again.
	alreadyDelivered bool

	mtx *sync.Mutex
}

func (t *Engine) shouldDeliver(s *broadcaststate) bool {
	f := t.GuardianStorage.getMaxExpectedFaults()

	s.mtx.Lock()
	defer s.mtx.Unlock()

	if s.alreadyDelivered {
		return false
	}

	if len(s.votes) < f*2+1 {
		return false
	}

	if s.messageDigest == nil {
		return false
	}

	nmVotes := 0
	for _, dgst := range s.votes {
		if dgst == *s.messageDigest {
			nmVotes++
		}
	}

	if nmVotes < f*2+1 {
		return false
	}

	s.alreadyDelivered = true

	return true
}

var ErrEquivicatingGuardian = fmt.Errorf("equivication, guardian sent two different messages for the same round and session")

func (t *Engine) updateState(s *broadcaststate, msg *tsscommv1.SignedMessage, echoer *tsscommv1.PartyId) (shouldEcho bool, err error) {
	if s.messageDigest == nil {
		return false, fmt.Errorf("state doesn't have a message digest")
	}
	// this is a SECURITY measure to prevent equivication attacks:
	// It is possible that the same guardian sends two different messages for the same round and session.
	// We do not accept messages with the same uuid and different content.
	if *s.messageDigest != hashSignedMessage(msg) {
		if err := t.verifySignedMessage(msg); err == nil { // no error means the sender is the equivicator.
			return false, fmt.Errorf("%w:%v", ErrEquivicatingGuardian, msg.Sender)
		}

		return false, fmt.Errorf("%w:%v", ErrEquivicatingGuardian, echoer)
	}

	f := t.GuardianStorage.getMaxExpectedFaults()

	return s.update(echoer, msg, f)
}

func (s *broadcaststate) update(echoer *tsscommv1.PartyId, msg *tsscommv1.SignedMessage, f int) (shouldEcho bool, err error) {
	isMsgSrc := equalPartyIds(protoToPartyId(echoer), protoToPartyId(msg.Sender))

	s.mtx.Lock()
	defer s.mtx.Unlock()

	s.votes[voterId(echoer.Id)] = hashSignedMessage(msg)
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
	// since threshold is 2/3*n+1, f = (st.Threshold - 1) / 2
	// in our case st.Threshold is not inclusive, so we don't need to subtract 1.
	return (st.Threshold) / 2 // this is the floor of the result.
}

// broadcastInspection is responsible for either reliable-broadcast logic (Bracha's algorithm),
// or hashed-broadcast channel logic (similar but less robust - without message duplications).
// Not allowed to authorise echoing.
func (t *Engine) broadcastInspection(msg Incoming) (shouldDeliver bool, err error) {
	if t.UseReliableBroadcast {
		return false, fmt.Errorf("received hashed message, but reliable broadcast is enabled")
	}

	hashed := msg.toEcho().Echoed.(*tsscommv1.Echo_Hashed).Hashed
	echoer := msg.GetSource()

	uid := uuid{}
	copy(uid[:], hashed.Uuid)

	state, err := t.fetchOrCreateState(uid, nil, hashed)
	if err != nil {
		return false, err
	}

	if err := state.updateFromHashed(hashed, echoer); err != nil {
		return false, err
	}

	if t.shouldDeliver(state) {
		return true, nil
	}

	return false, nil
}

func (s *broadcaststate) updateFromHashed(hashed *tsscommv1.HashedMessage, echoer *tsscommv1.PartyId) error {
	panic("not implemented")
}

func (t *Engine) relbroadcastInspection(parsed tss.ParsedMessage, msg Incoming) (shouldEcho bool, shouldDeliver bool, err error) {
	// No need to check input: it was already checked before reaching this point

	signed := msg.toEcho().Echoed.(*tsscommv1.Echo_Message).Message
	echoer := msg.GetSource()

	uuid, err := t.getMessageUUID(parsed)
	if err != nil {
		return false, false, err
	}

	if parsed.WireMsg() == nil || parsed.WireMsg().TrackingID == nil {
		return false, false, fmt.Errorf("tracking id is nil")
	}

	state, err := t.fetchOrCreateState(uuid, parsed.WireMsg().TrackingID, signed)
	if err != nil {
		return false, false, err
	}

	// If we weren't using TLS - at this point we would have to verify the
	// signature of the echoer (sender).

	allowedToBroadcast, err := t.updateState(state, signed, echoer)
	if err != nil {
		return false, false, err
	}

	if t.shouldDeliver(state) {
		return allowedToBroadcast, true, nil
	}

	return allowedToBroadcast, false, nil
}

func (t *Engine) fetchOrCreateState(uuid uuid, trackingId []byte, echoedContent any) (*broadcaststate, error) {
	t.mtx.Lock()
	defer t.mtx.Unlock()

	signed := echoedContent.(*tsscommv1.SignedMessage)
	// depends on the echoedContent
	state, ok := t.received[uuid]
	if ok {
		return state, nil
	}

	if err := t.verifySignedMessage(signed); err != nil {
		return nil, err
	}

	hshd := hashSignedMessage(signed)
	state = &broadcaststate{
		timeReceived:  time.Now(),
		messageDigest: &hshd,

		trackingId: trackingId,

		votes:            make(map[voterId]digest),
		echoedAlready:    false,
		alreadyDelivered: false,
		mtx:              &sync.Mutex{},
	}

	t.received[uuid] = state

	return state, nil
}
