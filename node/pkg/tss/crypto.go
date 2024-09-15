package tss

import (
	tsscommv1 "github.com/certusone/wormhole/node/pkg/proto/tsscomm/v1"
	"golang.org/x/crypto/sha3"
)

type digest [32]byte

type signature []byte

func hash(msg []byte) digest {
	d := sha3.Sum256(msg)
	return d
}
func (t *Engine) authAndDecrypt(maccedMsg *tsscommv1.SignedMessage) error {
	// TODO
	return nil
}

func (t *Engine) encryptAndMac(msg *tsscommv1.SignedMessage) {
	if msg.Sender == nil {
		msg.Sender = partyIdToProto(t.Self)
	}

	msg.Authentication = &tsscommv1.SignedMessage_MAC{
		MAC: []byte("signature"),
	}
}

func (t *Engine) sign(msg *tsscommv1.SignedMessage) {
	if msg.Sender == nil {
		msg.Sender = partyIdToProto(t.Self)
	}
	msg.Authentication = &tsscommv1.SignedMessage_Signature{
		Signature: []byte("signature"),
	}
}

func (st *GuardianStorage) verifyEcho(msg *tsscommv1.Echo) error {
	// TODO
	return nil
}
func (t *Engine) signEcho(msg *tsscommv1.Echo) error {
	msg.Echoer = partyIdToProto(t.Self)
	msg.Signature = []byte("signature")
	return nil
}

func (st *GuardianStorage) verifySignedMessage(msg *tsscommv1.SignedMessage) error {
	// TODO
	return nil
}
