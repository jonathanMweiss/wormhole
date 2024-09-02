package tss

import (
	"fmt"

	gossipv1 "github.com/certusone/wormhole/node/pkg/proto/gossip/v1"
	"github.com/yossigi/tss-lib/v2/ecdsa/signing"
	"github.com/yossigi/tss-lib/v2/tss"
)

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

func vaidateEchoCorrectForm(e *gossipv1.Echo) error {
	if e == nil {
		return fmt.Errorf("echo is nil")
	}

	if e.Signature == nil {
		return fmt.Errorf("echo doesn't contain a signature")
	}

	if err := validatePartIdProtoCorrectForm(e.Echoer); err != nil {
		return err
	}

	return validateSignedMessageCorrectForm(e.Message)
}

func validatePartIdProtoCorrectForm(p *gossipv1.PartyId) error {
	if p == nil {
		return fmt.Errorf("party id is nil")
	}

	if p.Id == "" {
		return fmt.Errorf("party id doesn't contain an id")
	}

	if p.Key == nil {
		return fmt.Errorf("party id doesn't contain a key")
	}

	return nil

}

func validateSignedMessageCorrectForm(m *gossipv1.SignedMessage) error {
	if m == nil {
		return fmt.Errorf("signed message is nil")
	}

	if err := validatePartIdProtoCorrectForm(m.Sender); err != nil {
		return err
	}

	if m.Payload == nil {
		return fmt.Errorf("signed message doesn't contain a payload")
	}

	for _, v := range m.Recipients {
		if err := validatePartIdProtoCorrectForm(v); err != nil {
			return err
		}
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
