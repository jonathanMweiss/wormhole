package tss

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	gossipv1 "github.com/certusone/wormhole/node/pkg/proto/gossip/v1"
	"github.com/certusone/wormhole/node/pkg/supervisor"
	ethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/yossigi/tss-lib/v2/common"
	tssutil "github.com/yossigi/tss-lib/v2/ecdsa/ethereum"
	"github.com/yossigi/tss-lib/v2/ecdsa/keygen"
	"github.com/yossigi/tss-lib/v2/ecdsa/party"
	"github.com/yossigi/tss-lib/v2/tss"
	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"
)

type symKey []byte

// Engine is the implementation of reliableTSS, it is a wrapper for the tss-lib fullParty and adds reliable broadcast logic
// to the message sending and receiving.
type Engine struct {
	ctx context.Context

	logger *zap.Logger
	GuardianStorage

	fp party.FullParty

	// TODO We must ensure someone ALWAYS listens on these channels, and does nothing else.
	// Otherwise, we might have a circular dependancy blocking the engine/FullParty from working.
	fpOutChan      chan tss.Message
	fpSigOutChan   chan *common.SignatureData
	messageOutChan chan *gossipv1.GossipMessage
	fpErrChannel   chan *tss.Error // used to log issues from the FullParty.

	started         atomic.Uint32
	msgSerialNumber uint64

	// used to perform reliable broadcast:
	mtx      *sync.Mutex
	received map[digest]*broadcaststate
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

	// Assumes threshold = 2f+1, where f is the maximal expected number of faulty nodes.
	Threshold int

	// all secret keys should be generated with specific value.
	SavedSecretParameters *keygen.LocalPartySaveData

	signingKey *ecdsa.PrivateKey // should be the unmarshalled value of signing key.
	Symkeys    []symKey          // should be generated upon creation using DH shared key protocol if nil.

	LoadDistributionKey []byte
}

func (g *GuardianStorage) contains(pid *tss.PartyID) bool {
	for _, v := range g.Guardians {
		if equalPartyIds(pid, v) {
			return true
		}
	}

	return false
}

// GuardianStorageFromFile loads a guardian storage from a file.
// If the storage file hadn't contained symetric keys, it'll compute them.
func NewGuardianStorageFromFile(storagePath string) (*GuardianStorage, error) {
	var storage GuardianStorage
	if err := storage.load(storagePath); err != nil {
		return nil, err
	}

	return &storage, nil
}

// ProducedSignature lets a listener receive the output signatures once they're ready.
func (t *Engine) ProducedSignature() <-chan *common.SignatureData {
	return t.fpSigOutChan
}

// ProducedOutputMessages ensures a listener can send the output messages to the network.
func (t *Engine) ProducedOutputMessages() <-chan *gossipv1.GossipMessage {
	return t.messageOutChan
}

// BeginAsyncThresholdSigningProtocol used to start the TSS protocol over a specific msg.
func (t *Engine) BeginAsyncThresholdSigningProtocol(vaaDigest []byte) error {
	if t == nil {
		return fmt.Errorf("tss engine is nil")
	}
	if t.started.Load() != started {
		return fmt.Errorf("tss engine hasn't started")
	}

	if t.fp == nil {
		return fmt.Errorf("tss engine is not set up correctly, use NewReliableTSS to create a new engine")
	}

	if len(vaaDigest) != digestSize {
		return fmt.Errorf("vaaDigest length is not 32 bytes")
	}

	d := party.Digest{}
	copy(d[:], vaaDigest)

	// fmt.Printf("guardian %v started signing protocol: %v\n", t.GuardianStorage.Self.Index, d)
	return t.fp.AsyncRequestNewSignature(d)
}

func NewReliableTSS(storage *GuardianStorage) (ReliableTSS, error) {
	if storage == nil {
		return nil, fmt.Errorf("the guardian's tss storage is nil")
	}
	// fmt.Println("guardian storage loaded, threshold is:	", storage.Threshold)

	fpParams := party.Parameters{
		SavedSecrets:         storage.SavedSecretParameters,
		PartyIDs:             storage.Guardians,
		Self:                 storage.Self,
		Threshold:            storage.Threshold,
		WorkDir:              "",
		MaxSignerTTL:         time.Minute * 5,
		LoadDistributionSeed: storage.LoadDistributionKey,
	}

	fp, err := party.NewFullParty(&fpParams)
	if err != nil {
		return nil, err
	}

	fpOutChan := make(chan tss.Message) // this one must listen on it, and output to the p2p network.
	fpSigOutChan := make(chan *common.SignatureData)
	fpErrChannel := make(chan *tss.Error)

	t := &Engine{
		ctx: nil,

		logger:          &zap.Logger{},
		GuardianStorage: *storage,

		fp:              fp,
		fpOutChan:       fpOutChan,
		fpSigOutChan:    fpSigOutChan,
		fpErrChannel:    fpErrChannel,
		messageOutChan:  make(chan *gossipv1.GossipMessage),
		msgSerialNumber: 0,
		mtx:             &sync.Mutex{},
		received:        map[digest]*broadcaststate{},

		started: atomic.Uint32{}, // default value is 0
	}

	return t, nil
}

// Start starts the TSS engine, and listens for the outputs of the full party.
func (t *Engine) Start(ctx context.Context) error {
	if t == nil {
		return fmt.Errorf("tss engine is nil")
	}

	if !t.started.CompareAndSwap(notStarted, started) {
		return fmt.Errorf("tss engine has already started")
	}

	logger := supervisor.Logger(ctx)

	t.ctx = ctx
	t.logger = logger

	if err := t.fp.Start(t.fpOutChan, t.fpSigOutChan, t.fpErrChannel); err != nil {
		t.started.Store(notStarted)
		return err
	}
	// closing the t.fp.start inside th listener

	go t.fpListener()

	t.logger.Info("tss engine started")

	return nil
}

func (t *Engine) GetPublicKey() *ecdsa.PublicKey {
	return t.fp.GetPublic()
}

func (t *Engine) GetEthAddress() ethcommon.Address {
	pubkey := t.fp.GetPublic()
	ethAddBytes := ethcommon.LeftPadBytes(crypto.Keccak256(tssutil.EcdsaPublicKeyToBytes(pubkey)[1:])[12:], 32)
	return ethcommon.BytesToAddress(ethAddBytes)
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
				t.logger.Error(
					"failed to convert tss message to gossip message",
					zap.Error(err),
				)
				continue
			}

			t.messageOutChan <- tssMsg
		case err := <-t.fpErrChannel:
			// TODO: Do we need to add to the error the Digest that this error is related to?
			t.logger.Error("Error while generating TSS signature", zap.Error(err))
		}
	}
}

func (t *Engine) intoGossipMessage(m tss.Message) (*gossipv1.GossipMessage, error) {
	bts, routing, err := m.WireBytes()
	if err != nil {
		return nil, err
	}

	indices := make([]*gossipv1.PartyId, 0, len(routing.To))
	for _, pId := range routing.To {
		indices = append(indices, partyIdToProto(pId))
	}

	msgToSend := &gossipv1.SignedMessage{
		Payload:         bts,
		Sender:          partyIdToProto(m.GetFrom()),
		Recipients:      indices,
		MsgSerialNumber: atomic.AddUint64(&t.msgSerialNumber, 1),
		Authentication:  nil,
	}

	tssMsg := &gossipv1.PropagatedMessage{} // TODO: Once we use dedicated connections, we can remove this wrapper message.

	if routing.IsBroadcast || len(routing.To) == 0 || len(routing.To) > 1 {
		t.sign(msgToSend)
		echo := &gossipv1.PropagatedMessage_Echo{
			Echo: &gossipv1.Echo{
				Message: msgToSend,
				// TODO: Once we use two-way-TLS, we can remove this field
				// (just ensure we receive the message from the correct grpc stream).
				Signature: nil,
				Echoer:    partyIdToProto(m.GetFrom()),
			},
		}

		if err := t.signEcho(echo.Echo); err != nil {
			return nil, err
		}

		tssMsg.Payload = echo

	} else {
		// TODO: remove this since we plan on using two-way-TLS connections.
		t.encryptAndMac(msgToSend)
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

	switch m := msg.TssMessage.Payload.(type) {
	case *gossipv1.PropagatedMessage_Unicast:
		if err := t.handleUnicast(m); err != nil {
			// TODO: log?
			return
		}
	case *gossipv1.PropagatedMessage_Echo:
		shouldEcho, err := t.handleEcho(m)
		if err != nil {
			// TODO: log?
		}

		if !shouldEcho {
			return
		}

		if err := t.sendEchoOut(m); err != nil {
			return // TODO log.
		}
	}
}

func (t *Engine) sendEchoOut(m *gossipv1.PropagatedMessage_Echo) error {
	echo, _ := proto.Clone(m.Echo).(*gossipv1.Echo)
	if err := t.signEcho(echo); err != nil {
		return err
	}

	select {
	case <-t.ctx.Done():
		return t.ctx.Err()
	case t.messageOutChan <- &gossipv1.GossipMessage{
		Message: &gossipv1.GossipMessage_TssMessage{
			TssMessage: &gossipv1.PropagatedMessage{
				Payload: &gossipv1.PropagatedMessage_Echo{
					Echo: echo,
				},
			},
		},
	}:
	}

	return nil
}

var errBadRoundsInEcho = fmt.Errorf("cannot receive echos for rounds: %v,%v", round1Message1, round2Message)

func (t *Engine) handleEcho(m *gossipv1.PropagatedMessage_Echo) (bool, error) {
	parsed, err := t.parseEcho(m)
	if err != nil {
		return false, fmt.Errorf("couldn't parse echo: %w", err)
	}

	rnd, err := getRound(parsed)
	if err != nil {
		return false, fmt.Errorf("couldn't extract round from echo: %w", err)
	}

	if rnd == round1Message1 || rnd == round2Message {
		return false, errBadRoundsInEcho
	}

	shouldEcho, shouldDeliver, err := t.relbroadcastInspection(parsed, m.Echo)
	if err != nil {
		return false, fmt.Errorf("reliable broadcast inspection issue: %w", err)
	}

	if !shouldDeliver {
		return shouldEcho, nil
	}

	if err := t.fp.Update(parsed); err != nil {
		return shouldEcho, fmt.Errorf("failed to update the full party: %w", err)
	}

	return shouldEcho, nil
}

var errUnicastBadRound = fmt.Errorf("bad round for unicast (can accept round1Message1 and round2Message)")

func (t *Engine) handleUnicast(m *gossipv1.PropagatedMessage_Unicast) error {
	parsed, err := t.parseUnicast(m)
	if err != nil {
		if err == errUnicastNotForMe {
			return nil
		}
		return fmt.Errorf("malformed message: %w", err)
	}

	rnd, err := getRound(parsed)
	if err != nil {
		return fmt.Errorf("couldn't extract round from unicast: %w", err)
	}

	// only round 1 and round 2 are unicasts.
	if rnd != round1Message1 && rnd != round2Message {
		return errUnicastBadRound
	}

	if err := t.validateUnicastDoesntExist(parsed); err != nil {
		return fmt.Errorf("failed to ensure no equivication present in unicast: %w", err)
	}

	if err := t.fp.Update(parsed); err != nil {
		return fmt.Errorf("failed to update the full party: %w", err)
	}

	return nil
}

func (t *Engine) validateUnicastDoesntExist(parsed tss.ParsedMessage) error {
	id, err := t.getMessageUUID(parsed)
	if err != nil {
		return err
	}

	t.mtx.Lock()
	defer t.mtx.Unlock()
	if _, ok := t.received[id]; ok {
		return ErrEquivicatingGuardian
	}

	t.received[id] = &broadcaststate{
		timeReceived:  time.Now(), // used for GC.
		message:       nil,        // no need to store the content.
		messageDigest: digest{},   // no need to check content, since we never accept another.
		votes:         nil,        // no votes should be stored for a unicast.
		echoedAlready: true,       // ensuring this never echoed since it is a unicast.
		mtx:           nil,        // no need to lock this, just store it.
	}

	return nil
}

var (
	ErrUnkownEchoer = fmt.Errorf("echoer is not a known guardian")
	ErrUnkownSender = fmt.Errorf("sender is not a known guardian")
)

func (t *Engine) parseEcho(m *gossipv1.PropagatedMessage_Echo) (tss.ParsedMessage, error) {
	echoMsg := m.Echo

	if err := vaidateEchoCorrectForm(echoMsg); err != nil {
		return nil, err
	}

	if !t.GuardianStorage.contains(protoToPartyId(echoMsg.Echoer)) {
		return nil, ErrUnkownEchoer
	}

	senderPid := protoToPartyId(echoMsg.Message.Sender)
	if !t.GuardianStorage.contains(senderPid) {
		return nil, ErrUnkownSender
	}

	return tss.ParseWireMessage(echoMsg.Message.Payload, senderPid, true)
}

// SECURITY NOTE: this function ensure no equivocation.
func (t *Engine) getMessageUUID(msg tss.ParsedMessage) (digest, error) {
	// We don't add the content of the message to the uuid, othewrwise we won't be able to detect equivocations.

	d := append([]byte("tssMsgUUID:"), t.GuardianStorage.LoadDistributionKey...)

	// Since the digest of a parsedMessage is tied to the run of the protocol for a single signature, we use it as a sessionId
	msgdgst := msg.WireMsg().Digest
	cpy := make([]byte, len(msgdgst))
	copy(cpy, msgdgst)

	d = append(d, cpy...)

	// adding the sender, ensuring it is tied to the message.
	d = append(d, msg.GetFrom().Key...)
	d = append(d, []byte(msg.GetFrom().Id)...)

	// Adding the round to ensure no equivocation. That is,
	// we mustn't allow some sender j to send two different messages to the same round, in the same SessionID.
	rnd, err := getRound(msg)
	if err != nil {
		return digest{}, err
	}
	d = append(d, []byte(rnd)...)

	return hash(d), nil

}

var errUnicastNotForMe = fmt.Errorf("unicast message is not for me")

func (t *Engine) parseUnicast(m *gossipv1.PropagatedMessage_Unicast) (tss.ParsedMessage, error) {
	msg := m.Unicast

	if err := validateSignedMessageCorrectForm(msg); err != nil {
		return nil, err
	}

	if !t.isUnicastForMe(msg) {
		return nil, errUnicastNotForMe
	}

	senderPid := protoToPartyId(msg.Sender)
	if !t.GuardianStorage.contains(senderPid) {
		return nil, ErrUnkownSender
	}

	return tss.ParseWireMessage(msg.Payload, senderPid, false)
}

func (t *Engine) isUnicastForMe(msg *gossipv1.SignedMessage) bool {
	for _, v := range msg.Recipients {
		if equalPartyIds(protoToPartyId(v), t.Self) {
			return true
		}
	}

	return false
}
