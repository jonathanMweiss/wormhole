package tss

import (
	"fmt"

	gossipv1 "github.com/certusone/wormhole/node/pkg/proto/gossip/v1"
	"github.com/yossigi/tss-lib/v2/ecdsa/signing"
	"github.com/yossigi/tss-lib/v2/tss"
	"go.uber.org/zap"
)

type logableError struct {
	cause      error
	trackingId []byte
	round      signingRound // TODO: consider, it might require following the state of the fullParty per message.
}

func (l logableError) Error() string {
	if l.cause == nil {
		return ""
	}
	return l.cause.Error()
}

// Unwrap ensures logableError supports errors.Is and errors.As methods.
func (l logableError) Unwrap() error {
	return l.cause
}

func logErr(l *zap.Logger, err error) {
	if l == nil {
		return
	}

	if err == nil {
		return
	}

	informativeErr, ok := err.(logableError)
	if !ok {
		l.Error(err.Error())
		return
	}

	switch {
	case informativeErr.round != "", informativeErr.trackingId != nil:
		l.Error(
			informativeErr.Error(),
			zap.String("round", string(informativeErr.round)),
			zap.String("trackingId", fmt.Sprintf("%x", informativeErr.trackingId)),
		)
	case informativeErr.trackingId != nil:
		l.Error(
			informativeErr.Error(),
			zap.String("trackingId", fmt.Sprintf("%x", informativeErr.trackingId)),
		)
	case informativeErr.round != "":
		l.Error(
			informativeErr.Error(),
			zap.String("round", string(informativeErr.round)),
		)
	}
}

func equalPartyIds(a, b *tss.PartyID) bool {
	return a.Id == b.Id && string(a.Key) == string(b.Key)
}

func protoToPartyId(pid *gossipv1.PartyId) *tss.PartyID {
	return &tss.PartyID{
		MessageWrapper_PartyID: &tss.MessageWrapper_PartyID{
			Id:      pid.Id,
			Moniker: pid.Moniker,
			Key:     pid.Key,
		},
		Index: int(pid.Index),
	}
}

func partyIdToProto(pid *tss.PartyID) *gossipv1.PartyId {
	return &gossipv1.PartyId{
		Id:      pid.Id,
		Moniker: pid.Moniker,
		Key:     pid.Key,
		Index:   uint32(pid.Index),
	}
}

var (
	ErrEchoIsNil             = fmt.Errorf("echo is nil")
	ErrNoEchoSignature       = fmt.Errorf("echo doesn't contain a signature")
	ErrNoAuthenticationField = fmt.Errorf("SignedMessage doesn't contain an authentication field")
	ErrNilPartyId            = fmt.Errorf("party id is nil")
	ErrEmptyIDInPID          = fmt.Errorf("partyId identifier is empty")
	ErrEmptyKeyInPID         = fmt.Errorf("partyId doesn't contain a key")
	ErrSignedMessageIsNil    = fmt.Errorf("SignedMessage is nil")
	ErrNilPayload            = fmt.Errorf("SignedMessage doesn't contain a payload")
)

func vaidateEchoCorrectForm(e *gossipv1.Echo) error {
	if e == nil {
		return ErrEchoIsNil
	}

	if e.Signature == nil {
		return ErrNoEchoSignature
	}

	if err := validatePartIdProtoCorrectForm(e.Echoer); err != nil {
		return err
	}

	if err := validateSignedMessageCorrectForm(e.Message); err != nil {
		return fmt.Errorf("echo message error:%w", err)
	}

	return nil
}

func validatePartIdProtoCorrectForm(p *gossipv1.PartyId) error {
	if p == nil {
		return ErrNilPartyId
	}

	if p.Id == "" {
		return ErrEmptyIDInPID
	}

	if len(p.Key) == 0 {
		return ErrEmptyKeyInPID
	}

	return nil

}

func validateSignedMessageCorrectForm(m *gossipv1.SignedMessage) error {
	if m == nil {
		return ErrSignedMessageIsNil
	}

	if err := validatePartIdProtoCorrectForm(m.Sender); err != nil {
		return fmt.Errorf("signedMessage sender pID error:%w", err)
	}

	if m.Payload == nil {
		return ErrNilPayload
	}

	for _, v := range m.Recipients {
		if err := validatePartIdProtoCorrectForm(v); err != nil {
			return err
		}
	}

	if m.Authentication == nil {
		return ErrNoAuthenticationField
	}

	if s, ok := m.Authentication.(*gossipv1.SignedMessage_Signature); ok && s.Signature == nil {
		return ErrNoAuthenticationField
	}

	if mac, ok := m.Authentication.(*gossipv1.SignedMessage_MAC); ok && mac.MAC == nil {
		return ErrNoAuthenticationField
	}

	return nil
}

type signingRound string

const (
	round1Message1 signingRound = "round1M1"
	round1Message2 signingRound = "round1M2"
	round2Message  signingRound = "round2"
	round3Message  signingRound = "round3"
	round4Message  signingRound = "round4"
	round5Message  signingRound = "round5"
	round6Message  signingRound = "round6"
	round7Message  signingRound = "round7"
	round8Message  signingRound = "round8"
	round9Message  signingRound = "round9"
)

var _intToRoundArr = []signingRound{"round1", round2Message, round3Message, round4Message, round5Message, round6Message, round7Message, round8Message, round9Message}

func intToRound(i int) signingRound {
	if i < 1 || i > 9 {
		return ""
	}
	return _intToRoundArr[i-1]
}

func getRound(m tss.ParsedMessage) (signingRound, error) {
	switch m.Content().(type) {
	case *signing.SignRound1Message1:
		return round1Message1, nil
	case *signing.SignRound1Message2:
		return round1Message2, nil
	case *signing.SignRound2Message:
		return round2Message, nil
	case *signing.SignRound3Message:
		return round3Message, nil
	case *signing.SignRound4Message:
		return round4Message, nil
	case *signing.SignRound5Message:
		return round5Message, nil
	case *signing.SignRound6Message:
		return round6Message, nil
	case *signing.SignRound7Message:
		return round7Message, nil
	case *signing.SignRound8Message:
		return round8Message, nil
	case *signing.SignRound9Message:
		return round9Message, nil
	default:
		return "", fmt.Errorf("unknown message type")
	}
}
