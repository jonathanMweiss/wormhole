package tss

import gossipv1 "github.com/certusone/wormhole/node/pkg/proto/gossip/v1"

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

func (st *GuardianStorage) verifySignedMessage(msg *gossipv1.SignedMessage) error {
	// TODO
	return nil
}
