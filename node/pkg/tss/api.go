package tss

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"

	tsscommv1 "github.com/certusone/wormhole/node/pkg/proto/tsscomm/v1"
	ethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/yossigi/tss-lib/v2/common"
)

type message interface {
	IsBroadcast() bool
	GetNetworkMessage() *tsscommv1.PropagatedMessage
}

type Sendable interface {
	message
	GetDestinations() []*tsscommv1.PartyId

	cloneSelf() Sendable // deep copy to avoid race condition in tests (ensuring no one shares the same sendable).
}

type Incoming interface {
	message
	IsUnicast() bool
	GetSource() *tsscommv1.PartyId

	toUnicast() *tsscommv1.TssContent
	toEcho() *tsscommv1.Echo
}

// ReliableMessenger is a component of tss, where it knows how to handle incoming tsscommv1.PropagatedMessage,
// it may produce messages (of type Sendable), which should be delivered to other guardians.
// these Sendable messages are produced by the tss engine, and are needed by the other guardians to
// complete a TSS round. In addition it supplies a server with certificates of any
// party member, including itself.
type ReliableMessenger interface {
	// HandleIncomingTssMessage receives a network `message`` and process it using a reliable-broadcast protocol.
	HandleIncomingTssMessage(msg Incoming)
	ProducedOutputMessages() <-chan Sendable // just need to propagate this through the p2p network

	// Utilities for servers:
	GetCertificate() *tls.Certificate // containing secret key.
	GetPeers() []*x509.Certificate    // containing public keys.
	// FetchPartyId returns the PartyId for a given certificate, it'll use the public key
	// in the certificate and match it to the public key expected to be found in `*tsscommv1.PartyId`.
	FetchPartyId(cert *x509.Certificate) (*tsscommv1.PartyId, error)
}

// Signer is the interface to give any component with the ability to authorise a new threshold signature over a message.
type Signer interface {
	BeginAsyncThresholdSigningProtocol(vaaDigest []byte) error
	ProducedSignature() <-chan *common.SignatureData

	GetPublicKey() *ecdsa.PublicKey
	GetEthAddress() ethcommon.Address
}

// ReliableTSS represents a TSS engine that can fully support logic of
// reliable broadcast needed for the security of TSS over the network.
type ReliableTSS interface {
	ReliableMessenger
	Signer
	Start(ctx context.Context) error
}
