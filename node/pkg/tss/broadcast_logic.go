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

	tssMessage tss.ParsedMessage

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

	if !s.isSet() {
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

func (t *Engine) updateStateFromSigned(s *broadcaststate, msg *tsscommv1.SignedMessage, echoer *tsscommv1.PartyId) (shouldEcho bool, err error) {
	if !s.isSet() {
		return false, fmt.Errorf("state is not set, can't updateFromSigned") // shouldn't reach this point.
	}

	// this is a SECURITY measure to prevent equivication attacks:
	// It is possible that the same guardian sends two different messages for the same round and session.
	// We do not accept messages with the same uuid and different content.
	if s.isEquivication(msg) {
		//checked in the fetchOrCreateState function, so it should never reach this point.
		return false, t.findEquivicator(msg, echoer)
	}

	f := t.GuardianStorage.getMaxExpectedFaults()

	return s.updateFromSigned(echoer, msg, f)
}

func (s *broadcaststate) isEquivication(msg *tsscommv1.SignedMessage) bool {
	return *s.messageDigest != hashSignedMessage(msg)
}

func (t *Engine) findEquivicator(msg *tsscommv1.SignedMessage, echoer *tsscommv1.PartyId) error {
	// no error means the sender is the equivicator.
	if err := t.verifySignedMessage(msg); err == nil {
		return fmt.Errorf("%w:%v", ErrEquivicatingGuardian, msg.Sender)
	}

	return fmt.Errorf("%w:%v", ErrEquivicatingGuardian, echoer)
}

func (s *broadcaststate) updateFromSigned(echoer *tsscommv1.PartyId, msg *tsscommv1.SignedMessage, f int) (shouldEcho bool, err error) {
	isMsgSrc := equalPartyIds(protoToPartyId(echoer), protoToPartyId(msg.Sender))

	s.mtx.Lock()
	defer s.mtx.Unlock()

	// No need to check for vote changing here:
	// if we reached this part, then the message was checked for equivication.
	// changing vote requires a signature on a different message, so it'll have a different digest.
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

// hashBroadcastInspection is responsible for hashed-broadcast channel logic when receiving echo with HashedMessage.
// mainly collect votes, and ensures that if f*2+1 saw the same digest for UUID, then once this engine sees the same UUID, it'll deliver it.
// if it hadn't seen 2f+1 messages, it wont deliver it.
// Not allowed to echo, since this function doesn't seen signed messages, only hashed echoes.
func (t *Engine) hashBroadcastInspection(hashed *tsscommv1.HashedMessage, echoer *tsscommv1.PartyId) (toDeliver tss.ParsedMessage, err error) {
	if t.UseReliableBroadcast {
		return toDeliver, fmt.Errorf("received hashed message, but reliable broadcast is enabled")
	}

	uid := uuid{}
	copy(uid[:], hashed.Uuid)

	state, err := t.fetchOrCreateState(uid, echoer, hashed, nil)
	if err != nil {
		return toDeliver, err
	}

	if err := state.updateFromHashed(hashed, echoer); err != nil {
		return toDeliver, err
	}

	if t.shouldDeliver(state) {
		toDeliver = state.tssMessage
	}

	return toDeliver, err
}

func (s *broadcaststate) updateFromHashed(hashed *tsscommv1.HashedMessage, echoer *tsscommv1.PartyId) error {
	s.mtx.Lock()
	defer s.mtx.Unlock()

	newVote := digest{}

	copy(newVote[:], hashed.Digest)

	if oldVote, ok := s.votes[voterId(echoer.Id)]; ok && oldVote != newVote {
		return fmt.Errorf("%v, changed its vote", echoer)
	}

	s.votes[voterId(echoer.Id)] = newVote

	return nil
}

// relbroadcastInspection is responsible for either reliable-broadcast logic (Bracha's algorithm),
// or for hashed-broadcast channel logic when receiving echo with SignedMessage.
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

	state, err := t.fetchOrCreateState(uuid, echoer, signed, parsed)
	if err != nil {
		return false, false, err
	}

	// If we weren't using TLS - at this point we would have to verify the
	// signature of the echoer (sender).

	allowedToBroadcast, err := t.updateStateFromSigned(state, signed, echoer)
	if err != nil {
		return false, false, err
	}

	if t.shouldDeliver(state) {
		return allowedToBroadcast, true, nil
	}

	return allowedToBroadcast, false, nil
}

func (t *Engine) fetchOrCreateState(uuid uuid, echoer *tsscommv1.PartyId, echoedContent any, parsed tss.ParsedMessage) (*broadcaststate, error) {
	t.mtx.Lock()
	defer t.mtx.Unlock()

	state, exists := t.received[uuid]
	if !exists {
		state = &broadcaststate{
			timeReceived:  time.Now(),
			messageDigest: nil,

			trackingId: nil,
			tssMessage: nil,

			votes:            make(map[voterId]digest),
			echoedAlready:    false,
			alreadyDelivered: false,
			mtx:              &sync.Mutex{},
		}

		t.received[uuid] = state
	}

	if _, ok := echoedContent.(*tsscommv1.HashedMessage); ok { // no more fields to add since hashed message. (no content or sig)
		return state, nil
	}

	// reaching this point means the message is not a hashed,
	// then it should be called with parsed + signed message.
	if parsed == nil {
		return nil, fmt.Errorf("parsed message is nil")
	}

	signed, ok := echoedContent.(*tsscommv1.SignedMessage)
	if !ok {
		return nil, fmt.Errorf("echoed content is not a signed message") // shouldn't happen, but just in case.
	}

	if state.isSet() {
		// if the state is set, then it already saw a signature and accepted it.
		// so this might be equivication, check if accepted different message:
		if state.isEquivication(signed) {
			return nil, t.findEquivicator(signed, echoer)
		}

		return state, nil
	}

	if err := t.verifySignedMessage(signed); err != nil {
		return nil, err
	}

	// setting the state to the message.
	msgDigest := hashSignedMessage(signed)

	state.tssMessage = parsed
	state.messageDigest = &msgDigest
	state.trackingId = parsed.WireMsg().TrackingID

	return state, nil
}

func (s *broadcaststate) isSet() bool {
	return s.tssMessage != nil && s.messageDigest != nil && s.trackingId != nil
}
