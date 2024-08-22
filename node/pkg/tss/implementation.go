package tss

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"sync/atomic"
	"time"

	gossipv1 "github.com/certusone/wormhole/node/pkg/proto/gossip/v1"
	"github.com/yossigi/tss-lib/v2/common"
	"github.com/yossigi/tss-lib/v2/ecdsa/keygen"
	"github.com/yossigi/tss-lib/v2/ecdsa/party"
	"github.com/yossigi/tss-lib/v2/tss"
	"go.uber.org/zap"
)

type symKey []byte

// Engine is the implementation of reliableTSS, it is a wrapper for the tss-lib fullParty and adds reliable broadcast logic
// to the message sending and receiving.
type Engine struct {
	ctx context.Context

	logger zap.Logger
	GuardianStorage

	fp party.FullParty
	//
	fpOutChan    chan tss.Message // this one must listen on it, and output to the p2p network.
	fpSigOutChan chan *common.SignatureData
	fpErrChannel chan *tss.Error

	gossipOutChan chan *gossipv1.GossipMessage

	started         bool
	msgSerialNumber uint64
}

// GuardianStorage is a struct that holds the data needed for a guardian to participate in the TSS protocol
// including its signing key, and the shared symmetric keys with other guardians.
// should be loaded from a file.
type GuardianStorage struct {
	Self *tss.PartyID

	//Stored sorted by Key. include Self.
	Guardians []*tss.PartyID

	// SecretKey is the marshaled secret key of ReliableTSS, used to genereate SymKeys and signingKey.
	SecretKey []byte

	Threshold int

	// all secret keys should be generated with specific value.
	SavedSecretParameters *keygen.LocalPartySaveData

	signingKey *ecdsa.PrivateKey // should be the unmarshalled value of signing key.
	Symkeys    []symKey          // should be generated upon creation using DH shared key protocol if nil.
}

// BeginAsyncThresholdSigningProtocol used to start the TSS protocol over a specific msg.
func (t *Engine) BeginAsyncThresholdSigningProtocol(digest []byte) error {
	if t == nil {
		return fmt.Errorf("tss engine is nil")
	}
	if !t.started {
		return fmt.Errorf("tss engine hasn't started")
	}

	if t.fp == nil {
		return fmt.Errorf("tss engine is not set up correctly, use NewReliableTSS to create a new engine")
	}

	if len(digest) != 32 {
		return fmt.Errorf("digest length is not 32 bytes")
	}

	d := party.Digest{}
	copy(d[:], digest)

	// fmt.Printf("guardian %v started signing protocol: %v\n", t.GuardianStorage.Self.Index, d)
	return t.fp.AsyncRequestNewSignature(d)
}

// ProducedOutputMessages implements ReliableTSS.
func (t *Engine) ProducedOutputMessages() <-chan *gossipv1.GossipMessage {
	return t.gossipOutChan
}

// GuardianStorageFromFile loads a guardian storage from a file.
// If the storage file hadn't contained symetric keys, it'll compute them.
func GuardianStorageFromFile(storagePath string) (*GuardianStorage, error) {
	var storage GuardianStorage
	if err := storage.load(storagePath); err != nil {
		return nil, err
	}

	return &storage, nil
}

// TODO: get a signature output channel, so the guardian can listen to outputs from this tssEngine.
func NewReliableTSS(storage *GuardianStorage) (*Engine, error) {
	if storage == nil {
		return nil, fmt.Errorf("the guardian's tss storage is nil")
	}
	// fmt.Println("guardian storage loaded, threshold is:	", storage.Threshold)

	fpParams := party.Parameters{
		SavedSecrets: storage.SavedSecretParameters,
		PartyIDs:     storage.Guardians,
		Self:         storage.Self,
		Threshold:    storage.Threshold,
		WorkDir:      "",
		MaxSignerTTL: time.Minute * 5,
	}

	fp, err := party.NewFullParty(&fpParams)
	if err != nil {
		return nil, err
	}

	fpOutChan := make(chan tss.Message) // this one must listen on it, and output to the p2p network.
	fpSigOutChan := make(chan *common.SignatureData)
	fpErrChannel := make(chan *tss.Error)

	t := &Engine{
		GuardianStorage: *storage,

		fp:           fp,
		fpOutChan:    fpOutChan,
		fpSigOutChan: fpSigOutChan,
		fpErrChannel: fpErrChannel,

		gossipOutChan: make(chan *gossipv1.GossipMessage),
	}

	return t, nil
}

// Start starts the TSS engine, and listens for the outputs of the full party.
func (t *Engine) Start(ctx context.Context) error {
	t.ctx = ctx

	if err := t.fp.Start(t.fpOutChan, t.fpSigOutChan, t.fpErrChannel); err != nil {
		return err
	}
	//closing the t.fp.start inside th listener

	go t.fpListener()

	t.started = true

	return nil
}

// fpListener serves as a listining loop for the full party outputs.
// ensures the FP isn't being blocked on writing to fpOutChan, and wraps the result into a gossip message.
func (t *Engine) fpListener() {
	for {
		select {
		case <-t.ctx.Done():
			fmt.Printf("guardian %v stopped its full party\n", t.GuardianStorage.Self.Index)
			t.fp.Stop()
			return
		case m := <-t.fpOutChan:
			tssMsg, err := t.intoGossipMessage(m)
			if err != nil {
				continue
			}

			// todo: ensure someone listens to this channel.
			//todo: wrap the message into a gossip message and output it to the network, sign (or encrypt and mac) it and send it.
			t.gossipOutChan <- tssMsg
			// fmt.Printf("guardian %v sent %v \n", t.GuardianStorage.Self.Index, m.Type())
		case <-t.fpSigOutChan:
			// fmt.Println("signature out!")
			// todo: find out who should get the signature.
		case err := <-t.fpErrChannel:
			_ = err // todo: log the error?
			// fmt.Printf("guardian %v received error %v \n", t.GuardianStorage.Self.Index, err)
		}
	}
}

func (t *Engine) intoGossipMessage(m tss.Message) (*gossipv1.GossipMessage, error) {
	bts, routing, err := m.WireBytes()
	if err != nil {
		return nil, err
	}

	tssMsg := &gossipv1.PropagatedMessage{}

	indices := make([]uint32, len(routing.To))
	for i, pId := range routing.To {
		indices[i] = uint32(pId.Index)
	}

	msgToSend := &gossipv1.SignedMessage{
		Payload:         bts,
		Sender:          uint32(t.Self.Index),
		Recipients:      indices,
		MsgSerialNumber: atomic.AddUint64(&t.msgSerialNumber, 1),
		Authentication:  nil,
	}

	if routing.IsBroadcast || len(routing.To) == 0 || len(routing.To) > 1 {
		t.sign(msgToSend)
		tssMsg.Payload = &gossipv1.PropagatedMessage_Echo{
			Echo: &gossipv1.Echo{
				Message:   msgToSend,
				Signature: nil, //  No sig here, it means this is the original sender of the message, and not a vote.
				Echoer:    0,   // TODO: use -1 since this is not an echo.
			},
		}
	} else {
		t.encryptAndMac(msgToSend)
		// encrypt then mac the msgToSend (payload encrypted, and mac the full &gossipv1.SignedMessage)
		tssMsg.Payload = &gossipv1.PropagatedMessage_Unicast{
			Unicast: msgToSend,
		}
	}

	return &gossipv1.GossipMessage{
		Message: &gossipv1.GossipMessage_TssMessage{
			TssMessage: tssMsg,
		},
	}, nil
}

func (t *Engine) HandleIncomingTssMessage(msg *gossipv1.GossipMessage_TssMessage) {
	if t == nil {
		return
	}

	defer func() {
		// todo: consider sending the message to be gossiped or not. perhaps it's a duplicate message?
	}()

	switch m := msg.TssMessage.Payload.(type) {
	case *gossipv1.PropagatedMessage_Unicast:
		parsed, err := t.handleUnicast(m)
		if err != nil {
			return
		}

		// TODO: add the uuid of this message to the set of received messages.
		t.fp.Update(parsed)
	case *gossipv1.PropagatedMessage_Echo:
		parsed, err := t.handleEcho(m)
		if err != nil {
			return
		}

		// fmt.Printf("guardian %v received from %v: %v\n", t.GuardianStorage.Self.Index, parsed.GetFrom().Index, parsed.Type())
		t.fp.Update(parsed)
	}
}

func (t *Engine) handleEcho(m *gossipv1.PropagatedMessage_Echo) (tss.ParsedMessage, error) {
	echoMsg := m.Echo
	if echoMsg == nil {
		return nil, fmt.Errorf("echo message is nil")
	}

	if err := t.verifySignedMessage(echoMsg.Message); err != nil {
		return nil, err
	}

	if echoMsg.Echoer > uint32(len(t.Guardians)) {
		return nil, fmt.Errorf("echoer index is out of range")
	}

	if err := t.verifyEcho(echoMsg); err != nil {
		return nil, err
	}

	parsed, err := tss.ParseWireMessage(echoMsg.Message.Payload, t.Guardians[echoMsg.Message.Sender], true)
	if err != nil {
		return nil, err
	}
	return parsed, nil
}

func (t *Engine) handleUnicast(m *gossipv1.PropagatedMessage_Unicast) (tss.ParsedMessage, error) {
	defer func() {

	}()

	maccedMsg := m.Unicast
	if maccedMsg == nil {
		return nil, fmt.Errorf("unicast message is nil")
	}

	if maccedMsg.Sender > uint32(len(t.Guardians)) {
		return nil, fmt.Errorf("sender index is out of range")
	}

	if !t.isUnicastForMe(maccedMsg) {
		return nil, fmt.Errorf("unicast message is not for me")
	}

	if err := t.authAndDecrypt(maccedMsg); err != nil {
		return nil, err
	}

	parsed, err := tss.ParseWireMessage(maccedMsg.Payload, t.Guardians[maccedMsg.Sender], false)
	if err != nil {
		return nil, err
	}
	return parsed, nil
}

func (t *Engine) isUnicastForMe(maccedMsg *gossipv1.SignedMessage) bool {
	for _, v := range maccedMsg.Recipients {
		if v == uint32(t.Self.Index) {
			return true
		}
	}

	return false
}
