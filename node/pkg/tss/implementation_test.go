package tss

import (
	"context"
	"fmt"
	"math/big"
	"math/rand"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/certusone/wormhole/node/pkg/internal/testutils"
	tsscommv1 "github.com/certusone/wormhole/node/pkg/proto/tsscomm/v1"
	"github.com/certusone/wormhole/node/pkg/supervisor"
	"github.com/stretchr/testify/assert"
	"github.com/yossigi/tss-lib/v2/ecdsa/party"
	"github.com/yossigi/tss-lib/v2/ecdsa/signing"
	"github.com/yossigi/tss-lib/v2/tss"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	unicastRounds   = []signingRound{round1Message1, round2Message}
	broadcastRounds = []signingRound{
		round1Message2,
		round3Message,
		round4Message,
		round5Message,
		round6Message,
		round7Message,
		round8Message,
		round9Message,
	}

	allRounds = append(unicastRounds, broadcastRounds...)
)

func loadMockGuardianStorage(gstorageIndex int) *GuardianStorage {
	path, err := testutils.GetMockGuardianTssStorage(gstorageIndex)
	if err != nil {
		panic(err)
	}

	st, err := NewGuardianStorageFromFile(path)
	if err != nil {
		panic(err)
	}
	return st
}

func parsedIntoEcho(a *assert.Assertions, t *Engine, parsed tss.ParsedMessage) *tsscommv1.Echo {
	payload, _, err := parsed.WireBytes()
	a.NoError(err)

	echo1 := &tsscommv1.Echo{
		Message: &tsscommv1.SignedMessage{
			Payload:         payload,
			Sender:          partyIdToProto(t.Self),
			Recipients:      nil,
			MsgSerialNumber: 0,
			Authentication:  nil,
		},
		Signature: []byte{},
		Echoer:    &tsscommv1.PartyId{},
	}

	a.NoError(t.signEcho(echo1))

	return echo1
}

func TestBroadcast(t *testing.T) {

	// The tests here rely on n=5, threshold=2, meaning 3 guardians are needed to sign (f<=1).
	t.Run("forLeaderCreatingMessage", func(t *testing.T) {
		a := assert.New(t)
		engines := loadGuardians(a)
		e1 := engines[0]
		// make parsedMessage, and insert into e1
		// then add another one for the same round.
		for j, rnd := range allRounds {
			parsed1 := generateFakeMessageWithRandomContent(e1.Self, e1.Self, rnd, party.Digest{byte(j)})
			// parsed1 := signing.NewSignRound3Message(e1.Self, big.NewInt(0), big.NewInt(0))

			shouldBroadcast, shouldDeliver, err := e1.relbroadcastInspection(parsed1, parsedIntoEcho(a, e1, parsed1))
			a.NoError(err)
			a.True(shouldBroadcast)
			a.False(shouldDeliver)
		}
	})

	t.Run("forEnoughEchos", func(t *testing.T) {
		a := assert.New(t)
		engines := loadGuardians(a)
		e1, e2, e3 := engines[0], engines[1], engines[2]

		// two different signers on an echo, meaning it will receive from two players.
		// since f=1 and we have f+1 echos: it should broadcast at the end of this test.
		for j, rnd := range allRounds {
			parsed1 := generateFakeMessageWithRandomContent(e1.Self, e1.Self, rnd, party.Digest{byte(j)})

			echo := parsedIntoEcho(a, e1, parsed1)
			a.NoError(e2.signEcho(echo))

			shouldBroadcast, shouldDeliver, err := e1.relbroadcastInspection(parsed1, echo)
			a.NoError(err)
			a.False(shouldBroadcast)
			a.False(shouldDeliver)

			a.NoError(e3.signEcho(echo))

			shouldBroadcast, shouldDeliver, err = e1.relbroadcastInspection(parsed1, echo)
			a.NoError(err)
			a.True(shouldBroadcast)
			a.False(shouldDeliver)
		}
	})
}

func TestDeliver(t *testing.T) {
	t.Run("After2fPlus1Messages", func(t *testing.T) {
		a := assert.New(t)
		engines := loadGuardians(a)
		e1, e2, e3 := engines[0], engines[1], engines[2]

		// two different signers on an echo, meaning it will receive from two players.
		// since f=1 and we have f+1 echos: it should broadcast at the end of this test.
		for j, rnd := range allRounds {
			parsed1 := generateFakeMessageWithRandomContent(e1.Self, e1.Self, rnd, party.Digest{byte(j)})

			echo := parsedIntoEcho(a, e1, parsed1)
			a.NoError(e2.signEcho(echo))

			shouldBroadcast, shouldDeliver, err := e1.relbroadcastInspection(parsed1, echo)
			a.NoError(err)
			a.False(shouldBroadcast)
			a.False(shouldDeliver)

			a.NoError(e3.signEcho(echo))

			shouldBroadcast, shouldDeliver, err = e1.relbroadcastInspection(parsed1, echo)
			a.NoError(err)
			a.True(shouldBroadcast)
			a.False(shouldDeliver)

			a.NoError(e1.signEcho(echo))

			shouldBroadcast, shouldDeliver, err = e1.relbroadcastInspection(parsed1, echo)
			a.NoError(err)
			a.False(shouldBroadcast)
			a.True(shouldDeliver)
		}
	})

	t.Run("doesn'tDeliverTwice", func(t *testing.T) {
		a := assert.New(t)
		engines := loadGuardians(a)
		e1, e2, e3, e4 := engines[0], engines[1], engines[2], engines[3]

		// two different signers on an echo, meaning it will receive from two players.
		// since f=1 and we have f+1 echos: it should broadcast at the end of this test.
		for j, rnd := range allRounds {
			parsed1 := generateFakeMessageWithRandomContent(e1.Self, e1.Self, rnd, party.Digest{byte(j)})
			echo := parsedIntoEcho(a, e1, parsed1)
			a.NoError(e2.signEcho(echo))

			shouldBroadcast, shouldDeliver, err := e1.relbroadcastInspection(parsed1, echo)
			a.NoError(err)
			a.False(shouldBroadcast)
			a.False(shouldDeliver)

			a.NoError(e3.signEcho(echo))

			shouldBroadcast, shouldDeliver, err = e1.relbroadcastInspection(parsed1, echo)
			a.NoError(err)
			a.True(shouldBroadcast)
			a.False(shouldDeliver)

			a.NoError(e1.signEcho(echo))

			shouldBroadcast, shouldDeliver, err = e1.relbroadcastInspection(parsed1, echo)
			a.NoError(err)
			a.False(shouldBroadcast)
			a.True(shouldDeliver)

			a.NoError(e4.signEcho(echo))

			shouldBroadcast, shouldDeliver, err = e1.relbroadcastInspection(parsed1, echo)
			a.NoError(err)
			a.False(shouldBroadcast)
			a.False(shouldDeliver)
		}
	})
}

func TestUuidNotAffectedByMessageContentChange(t *testing.T) {
	a := assert.New(t)
	engines := loadGuardians(a)
	e1 := engines[0]
	for i, rnd := range allRounds {
		trackingId := party.Digest{byte(i)}

		// each message is generated with some random content inside.
		parsed1 := generateFakeMessageWithRandomContent(e1.Self, e1.Self, rnd, trackingId)
		parsed2 := generateFakeMessageWithRandomContent(e1.Self, e1.Self, rnd, trackingId)

		uid1, err := e1.getMessageUUID(parsed1)
		a.NoError(err)

		uid2, err := e1.getMessageUUID(parsed2)
		a.NoError(err)
		a.Equal(uid1, uid2)
	}
}

func TestEquivocation(t *testing.T) {
	t.Run("inBroadcastLogic", func(t *testing.T) {
		a := assert.New(t)
		engines := loadGuardians(a)
		e1, e2 := engines[0], engines[1]

		for i, rndType := range allRounds {

			trackingId := party.Digest{byte(i)}

			parsed1 := generateFakeMessageWithRandomContent(e1.Self, e2.Self, rndType, trackingId)

			shouldBroadcast, shouldDeliver, err := e1.relbroadcastInspection(parsed1, parsedIntoEcho(a, e2, parsed1))
			a.NoError(err)
			a.True(shouldBroadcast) //should broadcast since e2 is the source of this message.
			a.False(shouldDeliver)

			parsed2 := generateFakeMessageWithRandomContent(e1.Self, e2.Self, rndType, trackingId)

			shouldBroadcast, shouldDeliver, err = e1.relbroadcastInspection(parsed2, parsedIntoEcho(a, e2, parsed2))
			a.ErrorAs(err, &ErrEquivicatingGuardian)
			a.False(shouldBroadcast)
			a.False(shouldDeliver)
		}
	})

	t.Run("inUnicast", func(t *testing.T) {
		a := assert.New(t)
		engines := loadGuardians(a)
		e1, e2 := engines[0], engines[1]

		for i, rndType := range unicastRounds {

			trackingId := party.Digest{byte(i)}

			parsed1 := generateFakeMessageWithRandomContent(e1.Self, e2.Self, rndType, trackingId)
			parsed2 := generateFakeMessageWithRandomContent(e1.Self, e2.Self, rndType, trackingId)

			bts, _, err := parsed1.WireBytes()
			a.NoError(err)
			msg := &tsscommv1.PropagatedMessage_Unicast{
				Unicast: &tsscommv1.SignedMessage{
					Payload:         bts,
					Sender:          partyIdToProto(e1.Self),
					Recipients:      []*tsscommv1.PartyId{partyIdToProto(e2.Self)},
					MsgSerialNumber: 0,
					Authentication: &tsscommv1.SignedMessage_MAC{
						MAC: []byte{1, 2, 3},
					},
				},
			}

			e2.handleUnicast(msg)

			bts, _, err = parsed2.WireBytes()
			a.NoError(err)
			msg.Unicast.Payload = bts
			a.ErrorIs(e2.handleUnicast(msg), ErrEquivicatingGuardian)
		}
	})
}

func TestBadSignatures(t *testing.T) {
	t.FailNow() // TODO
}
func TestE2E(t *testing.T) {
	// Setting up 5 engines, each with a different guardian storage.
	// all will attempt to sign a single message, while outputing messages to each other,
	// and reliably broadcasting them.

	a := assert.New(t)
	engines := loadGuardians(a)

	dgst := party.Digest{1, 2, 3, 4, 5, 6, 7, 8, 9}

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute*60)
	defer cancel()
	ctx = setSupervisor(ctx)

	fmt.Println("starting engines.")
	for _, engine := range engines {
		a.NoError(engine.Start(ctx))
	}

	fmt.Println("msgHandler settup:")
	dnchn := msgHandler(ctx, engines)

	fmt.Println("engines started, requesting sigs")
	// all engines are started, now we can begin the protocol.
	for _, engine := range engines {
		tmp := make([]byte, 32)
		copy(tmp, dgst[:])
		engine.BeginAsyncThresholdSigningProtocol(tmp)
	}
	select {
	case <-dnchn:
	case <-ctx.Done():
		t.FailNow()
	}
}

func setSupervisor(ctx context.Context) context.Context {
	var supervisedCtx context.Context

	logger := zap.New(
		zapcore.NewCore(
			zapcore.NewConsoleEncoder(zap.NewDevelopmentEncoderConfig()),
			zapcore.AddSync(zapcore.Lock(os.Stderr)),
			zap.NewAtomicLevelAt(zapcore.Level(zapcore.DebugLevel)),
		),
	)

	supervisor.New(ctx, logger, func(ctx context.Context) error {
		supervisedCtx = ctx
		<-ctx.Done()
		return ctx.Err()
	})

	return supervisedCtx
}

func TestMessagesWithBadRounds(t *testing.T) {
	a := assert.New(t)
	gs := loadGuardians(a)
	e1, e2 := gs[0], gs[1]
	from := e1.Self
	to := e2.Self

	t.Run("Unicast", func(t *testing.T) {
		msgDigest := party.Digest{1}
		for _, rnd := range broadcastRounds {
			parsed := generateFakeMessageWithRandomContent(from, to, rnd, msgDigest)
			bts, _, err := parsed.WireBytes()
			a.NoError(err)

			m := &tsscommv1.PropagatedMessage_Unicast{
				Unicast: &tsscommv1.SignedMessage{
					Payload:         bts,
					Sender:          partyIdToProto(from),
					Recipients:      []*tsscommv1.PartyId{partyIdToProto(to)},
					MsgSerialNumber: 0,
					Authentication: &tsscommv1.SignedMessage_MAC{
						MAC: []byte{1, 2, 3},
					},
				},
			}
			err = e2.handleUnicast(m)
			a.ErrorIs(err, errUnicastBadRound)
		}
	})

	t.Run("Echo", func(t *testing.T) {
		msgDigest := party.Digest{2}
		for _, rnd := range unicastRounds {
			parsed := generateFakeMessageWithRandomContent(from, to, rnd, msgDigest)
			bts, _, err := parsed.WireBytes()
			a.NoError(err)

			m := &tsscommv1.PropagatedMessage_Echo{
				Echo: &tsscommv1.Echo{
					Message: &tsscommv1.SignedMessage{
						Payload:         bts,
						Sender:          partyIdToProto(from),
						Recipients:      []*tsscommv1.PartyId{partyIdToProto(to)},
						MsgSerialNumber: 0,
						Authentication: &tsscommv1.SignedMessage_Signature{
							Signature: []byte{1, 2, 3},
						},
					},
					Signature: []byte{1, 2, 3},
					Echoer:    partyIdToProto(from),
				},
			}
			_, err = e2.handleEcho(m)
			a.ErrorIs(err, errBadRoundsInEcho)
		}
	})
}

// if to == nil it's a broadcast message.
func generateFakeMessageWithRandomContent(from, to *tss.PartyID, rnd signingRound, digest party.Digest) tss.ParsedMessage {
	trackingId := &big.Int{}
	trackingId.SetBytes(digest[:])

	rndmBigNumber := &big.Int{}
	buf := make([]byte, 16)
	rand.Read(buf)
	rndmBigNumber.SetBytes(buf)

	var (
		meta    = tss.MessageRouting{From: from, IsBroadcast: true}
		content tss.MessageContent
	)

	switch rnd {
	case round1Message1:
		if to == nil {
			panic("not a broadcast message")
		}
		meta = tss.MessageRouting{From: from, To: []*tss.PartyID{to}, IsBroadcast: false}
		content = &signing.SignRound1Message1{C: rndmBigNumber.Bytes()}
	case round1Message2:
		content = &signing.SignRound1Message2{Commitment: rndmBigNumber.Bytes()}
	case round2Message:
		if to == nil {
			panic("not a broadcast message")
		}
		meta = tss.MessageRouting{From: from, To: []*tss.PartyID{to}, IsBroadcast: false}
		content = &signing.SignRound2Message{C1: rndmBigNumber.Bytes()}
	case round3Message:
		content = &signing.SignRound3Message{Theta: rndmBigNumber.Bytes()}
	case round4Message:
		content = &signing.SignRound4Message{ProofAlphaX: rndmBigNumber.Bytes()}
	case round5Message:
		content = &signing.SignRound5Message{Commitment: rndmBigNumber.Bytes()}
	case round6Message:
		content = &signing.SignRound6Message{ProofAlphaX: rndmBigNumber.Bytes()}
	case round7Message:
		content = &signing.SignRound7Message{Commitment: rndmBigNumber.Bytes()}
	case round8Message:
		content = &signing.SignRound8Message{DeCommitment: [][]byte{rndmBigNumber.Bytes()}}
	case round9Message:
		content = &signing.SignRound9Message{S: rndmBigNumber.Bytes()}
	default:
		panic("unknown round")
	}

	return tss.NewMessage(meta, content, tss.NewMessageWrapper(meta, content, trackingId.Bytes()...))
}

func loadGuardians(a *assert.Assertions) []*Engine {
	engines := make([]*Engine, Participants)

	for i := 0; i < Participants; i++ {
		e, err := NewReliableTSS(loadMockGuardianStorage(i))
		a.NoError(err)
		engines[i] = e.(*Engine)
	}

	return engines
}

func msgHandler(ctx context.Context, engines []*Engine) chan struct{} {
	signalSuccess := make(chan struct{})
	once := sync.Once{}

	go func() {
		wg := sync.WaitGroup{}
		wg.Add(len(engines) * 2)

		chns := make([]chan *tsscommv1.PropagatedMessage, len(engines))
		for i := range chns {
			chns[i] = make(chan *tsscommv1.PropagatedMessage, 10000)
		}

		for i, e := range engines {
			i, engine := i, e

			// need a separate goroutine for handling engine output and engine input.
			// simulating network stream incoming and network stream outgoing.

			// incoming
			go func() {
				defer wg.Done()
				for {
					select {
					case <-ctx.Done():
						return
					case <-signalSuccess:
						return
					case msg := <-chns[i]:
						engine.HandleIncomingTssMessage(msg)
					}
				}
			}()

			//  Listener, responsible to receive output of engine, and direct it to the other engines.
			go func() {
				defer wg.Done()
				for {
					select {
					case <-ctx.Done():
						return
					case m := <-engine.ProducedOutputMessages():
						for _, feedChn := range chns { // treating everything as broadcast for ease of use.
							feedChn <- m
						}
					case <-engine.ProducedSignature():
						once.Do(func() { close(signalSuccess) })
						return // TODO verify signature.
					case <-signalSuccess:
						return
					}
				}
			}()
		}

		wg.Wait()
	}()

	return signalSuccess
}
