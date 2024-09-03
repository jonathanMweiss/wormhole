package tss

import (
	gossipv1 "github.com/certusone/wormhole/node/pkg/proto/gossip/v1"
	"golang.org/x/crypto/sha3"
)

type digest [32]byte

type signature []byte

func hash(msg []byte) digest {
	d := sha3.Sum256(msg)
	return d
}
func (t *Engine) authAndDecrypt(maccedMsg *gossipv1.SignedMessage) error {
	// TODO
	return nil
}

func (t *Engine) encryptAndMac(msgToSend *gossipv1.SignedMessage) {
	// TODO
}

func (t *Engine) sign(msg *gossipv1.SignedMessage) {
	// TODO
}

func (st *GuardianStorage) verifyEcho(msg *gossipv1.Echo) error {
	// TODO
	return nil
}
func (t *Engine) signEcho(msg *gossipv1.Echo) error {
	msg.Echoer = partyIdToProto(t.Self)
	return nil
}

func (st *GuardianStorage) verifySignedMessage(msg *gossipv1.SignedMessage) error {
	// TODO
	return nil
}
