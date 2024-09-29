package tss

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"

	tsscommv1 "github.com/certusone/wormhole/node/pkg/proto/tsscomm/v1"
	"github.com/wormhole-foundation/wormhole/sdk/vaa"
	"golang.org/x/crypto/sha3"
)

type digest [32]byte // TODO: Consider using the common.Hash they use in other places.

func hash(msg []byte) digest {
	d := sha3.Sum256(msg)
	return d
}

// using this function since proto.Marshal is either non-deterministic,
// or it isn't canonical - as stated in proto.MarshalOptions docs.

func hashSignedMessage(msg *tsscommv1.SignedMessage) digest {
	if msg == nil {
		return digest{}
	}

	b := bytes.NewBuffer(nil)
	b.Write(msg.Content.Payload)
	vaa.MustWrite(b, binary.BigEndian, msg.Content.MsgSerialNumber)
	writePartyID(b, msg.Sender)

	return hash(b.Bytes())
}

func writePartyID(writer io.Writer, id *tsscommv1.PartyId) {
	writer.Write([]byte(id.Id))
	writer.Write(id.Key)
	writer.Write([]byte(id.Moniker))
	vaa.MustWrite(writer, binary.BigEndian, id.Index)
}

func (t *Engine) sign(msg *tsscommv1.SignedMessage) error {
	if msg.Sender == nil {
		msg.Sender = partyIdToProto(t.Self)
	}
	digest := hashSignedMessage(msg)

	sig, err := t.GuardianStorage.signingKey.Sign(rand.Reader, digest[:], nil)
	msg.Signature = sig
	return err
}

var ErrInvalidSignature = fmt.Errorf("invalid signature")

var errEMptySignature = fmt.Errorf("empty signature")

func (st *GuardianStorage) verifySignedMessage(msg *tsscommv1.SignedMessage) error {
	if msg == nil {
		return fmt.Errorf("nil signed message")
	}

	if msg.Signature == nil {
		return errEMptySignature
	}

	cert, err := st.FetchCertificate(msg.Sender)
	if err != nil {
		return err
	}

	pk, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("certificated stored with non-ecdsa public key, guardian storage is corrupted")
	}

	digest := hashSignedMessage(msg)

	isValid := ecdsa.VerifyASN1(pk, digest[:], msg.Signature)

	if !isValid {
		return ErrInvalidSignature
	}

	return nil
}
