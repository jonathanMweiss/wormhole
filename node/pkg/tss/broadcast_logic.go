package tss

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sync"
	"time"

	tsscommv1 "github.com/certusone/wormhole/node/pkg/proto/tsscomm/v1"
	"github.com/wormhole-foundation/wormhole/sdk/vaa"
	"github.com/yossigi/tss-lib/v2/common"
	"github.com/yossigi/tss-lib/v2/tss"
)

// The following code follows Bracha's reliable broadcast algorithm.

// voterId is comprised from the id and key of the signer, should match the guardians (in GuardianStorage) id and key.
type voterId string

// We use the UUID to distinguish between messages the reliable broadcast algorithm handles.
// when supporting a new uuid, take careful considertaions.
// for instance, TSS messages create their uuid from values that make each message unique, but also
// ensure the reliable-broadcast can detect equivication attacks.
type hasUUID interface {
	getUUID(loadDistKey []byte) (uuid, error)
}
type parsedMsg interface {
	hasUUID // most important feature.
	wrapError(error) error
	getTrackingID() *common.TrackingID // can be nil too.
}

type parsedProblem struct {
	*tsscommv1.Problem
	issuer *tsscommv1.PartyId
}

// Ensures the parsedProblem implements the ftCommand interface.
func (p *parsedProblem) ftCmd() {}

const parsedProblemDomain = "tssProblemDomainSeperator"
const parsedProblemDomainlen = len(parsedProblemDomain)

func (p *parsedProblem) getTrackingID() *common.TrackingID {
	return nil
}

func (p *parsedProblem) wrapError(err error) error {
	return logableError{
		cause:      fmt.Errorf("error parsing problem, issuer %v: %w", p.issuer, err),
		trackingId: nil, // TODO: this trackingID doesn't make sense to no one, should we use it here?
		round:      "",
	}
}

func (p *parsedProblem) getUUID(distLoadKey []byte) (uuid, error) {
	b := bytes.NewBuffer(make([]byte, 0, 4+4+8+32+parsedProblemDomainlen)) // space for each of the values

	b.WriteString(parsedProblemDomain) // domain separation.

	b.Write(distLoadKey)

	vaa.MustWrite(b, binary.BigEndian, p.ChainID)
	vaa.MustWrite(b, binary.BigEndian, p.Emitter)
	vaa.MustWrite(b, binary.BigEndian, p.IssuingTime.AsTime().Unix())

	b.WriteString(partyIdToString(protoToPartyId(p.issuer)))

	return uuid(hash(b.Bytes())), nil
}

type parsedTsscontent struct {
	tss.ParsedMessage
	signingRound
}

func (msg *parsedTsscontent) getUUID(loadDistKey []byte) (uuid, error) {
	return getMessageUUID(msg.ParsedMessage, loadDistKey)
}

func (p *parsedTsscontent) wrapError(err error) error {
	if p == nil {
		return err
	}

	return logableError{
		cause:      err,
		trackingId: p.getTrackingID(),
		round:      p.signingRound,
	}
}

func (p *parsedTsscontent) getTrackingID() *common.TrackingID {
	if p == nil {
		return nil
	}

	if p.ParsedMessage == nil {
		return nil
	}

	if p.WireMsg() == nil {
		return nil
	}

	return p.WireMsg().GetTrackingID()
}

type broadcaststate struct {
	// The following three fields should not be changed after creation of broadcaststate:
	timeReceived  time.Time
	messageDigest digest
	trackingId    *common.TrackingID

	votes map[voterId]bool
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

	s.alreadyDelivered = true

	return true
}

var ErrEquivicatingGuardian = fmt.Errorf("equivication, guardian sent two different messages for the same round and session")

func (t *Engine) updateState(s *broadcaststate, msg *tsscommv1.SignedMessage, echoer *tsscommv1.PartyId) (shouldEcho bool, err error) {
	// this is a SECURITY measure to prevent equivication attacks:
	// It is possible that the same guardian sends two different messages for the same round and session.
	// We do not accept messages with the same uuid and different content.
	if s.messageDigest != hashSignedMessage(msg) {
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

	s.votes[voterId(echoer.Id)] = true
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

func (t *Engine) relbroadcastInspection(parsed parsedMsg, msg Incoming) (shouldEcho bool, shouldDeliver bool, err error) {
	// No need to check input: it was already checked before reaching this point

	signed := msg.toEcho().Message
	echoer := msg.GetSource()

	state, err := t.fetchOrCreateState(parsed, signed)
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

func (t *Engine) fetchOrCreateState(parsed parsedMsg, signed *tsscommv1.SignedMessage) (*broadcaststate, error) {
	uuid, err := parsed.getUUID(t.LoadDistributionKey)
	if err != nil {
		return nil, err
	}

	t.mtx.Lock()
	defer t.mtx.Unlock()
	state, ok := t.received[uuid]

	if ok {
		return state, nil
	}

	if err := t.verifySignedMessage(signed); err != nil {
		return nil, err
	}

	state = &broadcaststate{
		timeReceived:  time.Now(),
		messageDigest: hashSignedMessage(signed),

		trackingId: parsed.getTrackingID(),

		votes:            make(map[voterId]bool),
		echoedAlready:    false,
		alreadyDelivered: false,
		mtx:              &sync.Mutex{},
	}

	t.received[uuid] = state

	return state, nil
}
