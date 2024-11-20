package tss

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"math/rand"
	"sync"
	"testing"
	"time"

	"github.com/certusone/wormhole/node/pkg/internal/testutils"
	tsscommv1 "github.com/certusone/wormhole/node/pkg/proto/tsscomm/v1"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	tsscommon "github.com/yossigi/tss-lib/v2/common"
	"github.com/yossigi/tss-lib/v2/ecdsa/party"
	"github.com/yossigi/tss-lib/v2/ecdsa/signing"
	"github.com/yossigi/tss-lib/v2/tss"
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
var supctx context.Context

func init() {
	supctx = testutils.MakeSupervisorContext(context.Background())
}

func parsedIntoEcho(a *assert.Assertions, t *Engine, parsed tss.ParsedMessage) *IncomingMessage {
	payload, _, err := parsed.WireBytes()
	a.NoError(err)

	msg := &tsscommv1.Echo{
		Message: &tsscommv1.SignedMessage{
			Content: &tsscommv1.SignedMessage_TssContent{
				TssContent: &tsscommv1.TssContent{Payload: payload},
			},
			Sender:    partyIdToProto(t.Self),
			Signature: nil,
		},
	}
	a.NoError(t.sign(msg.Message))

	return &IncomingMessage{
		Source: partyIdToProto(t.Self),
		Content: &tsscommv1.PropagatedMessage{
			Message: &tsscommv1.PropagatedMessage_Echo{
				Echo: msg,
			},
		},
	}
}

func (i *IncomingMessage) setSource(id *tss.PartyID) {
	i.Source = partyIdToProto(id)
}

func TestBroadcast(t *testing.T) {

	// The tests here rely on n=5, threshold=2, meaning 3 guardians are needed to sign (f<=1).
	t.Run("forLeaderCreatingMessage", func(t *testing.T) {
		a := assert.New(t)
		// f = 1, n = 5
		engines := load5GuardiansSetupForBroadcastChecks(a)

		e1 := engines[0]
		// make parsedMessage, and insert into e1
		// then add another one for the same round.
		for j, rnd := range allRounds {
			parsed1 := generateFakeMessageWithRandomContent(e1.Self, e1.Self, rnd, party.Digest{byte(j)})

			echo := parsedIntoEcho(a, e1, parsed1)

			shouldBroadcast, shouldDeliver, err := e1.relbroadcastInspection(&parsedTsscontent{parsed1, ""}, echo)
			a.NoError(err)
			a.True(shouldBroadcast)
			a.False(shouldDeliver)
		}
	})

	t.Run("forEnoughEchos", func(t *testing.T) {
		a := assert.New(t)
		engines := load5GuardiansSetupForBroadcastChecks(a)
		e1, e2, e3 := engines[0], engines[1], engines[2]

		// two different signers on an echo, meaning it will receive from two players.
		// since f=1 and we have f+1 echos: it should broadcast at the end of this test.
		for j, rnd := range allRounds {
			parsed1 := generateFakeMessageWithRandomContent(e1.Self, e1.Self, rnd, party.Digest{byte(j)})

			echo := parsedIntoEcho(a, e1, parsed1)
			echo.setSource(e2.Self)

			shouldBroadcast, shouldDeliver, err := e1.relbroadcastInspection(&parsedTsscontent{parsed1, ""}, echo)
			a.NoError(err)
			a.False(shouldBroadcast)
			a.False(shouldDeliver)

			echo.setSource(e3.Self)

			shouldBroadcast, shouldDeliver, err = e1.relbroadcastInspection(&parsedTsscontent{parsed1, ""}, echo)
			a.NoError(err)
			a.True(shouldBroadcast)
			a.False(shouldDeliver)
		}
	})
}

func load5GuardiansSetupForBroadcastChecks(a *assert.Assertions) []*Engine {
	engines, err := _loadGuardians(5) // f=1, n=5.
	a.NoError(err)

	for _, v := range engines {
		v.GuardianStorage.Threshold = 2 // meaning 3 guardians are needed to sign.
	}

	return engines
}

func TestDeliver(t *testing.T) {
	t.Run("After2fPlus1Messages", func(t *testing.T) {
		a := assert.New(t)
		engines := load5GuardiansSetupForBroadcastChecks(a)
		e1, e2, e3 := engines[0], engines[1], engines[2]

		// two different signers on an echo, meaning it will receive from two players.
		// since f=1 and we have f+1 echos: it should broadcast at the end of this test.
		for j, rnd := range allRounds {
			parsed1 := generateFakeMessageWithRandomContent(e1.Self, e1.Self, rnd, party.Digest{byte(j)})

			echo := parsedIntoEcho(a, e1, parsed1)
			echo.setSource(e2.Self)

			shouldBroadcast, shouldDeliver, err := e1.relbroadcastInspection(&parsedTsscontent{parsed1, ""}, echo)
			a.NoError(err)
			a.False(shouldBroadcast)
			a.False(shouldDeliver)

			echo.setSource(e3.Self)

			shouldBroadcast, shouldDeliver, err = e1.relbroadcastInspection(&parsedTsscontent{parsed1, ""}, echo)
			a.NoError(err)
			a.True(shouldBroadcast)
			a.False(shouldDeliver)

			echo.setSource(e1.Self)

			shouldBroadcast, shouldDeliver, err = e1.relbroadcastInspection(&parsedTsscontent{parsed1, ""}, echo)
			a.NoError(err)
			a.False(shouldBroadcast)
			a.True(shouldDeliver)
		}
	})

	t.Run("doesn'tDeliverTwice", func(t *testing.T) {
		a := assert.New(t)
		engines := load5GuardiansSetupForBroadcastChecks(a)
		e1, e2, e3, e4 := engines[0], engines[1], engines[2], engines[3]

		// two different signers on an echo, meaning it will receive from two players.
		// since f=1 and we have f+1 echos: it should broadcast at the end of this test.
		for j, rnd := range allRounds {
			parsed1 := generateFakeMessageWithRandomContent(e1.Self, e1.Self, rnd, party.Digest{byte(j)})
			echo := parsedIntoEcho(a, e1, parsed1)
			echo.setSource(e2.Self)

			shouldBroadcast, shouldDeliver, err := e1.relbroadcastInspection(&parsedTsscontent{parsed1, ""}, echo)
			a.NoError(err)
			a.False(shouldBroadcast)
			a.False(shouldDeliver)

			echo.setSource(e3.Self)

			shouldBroadcast, shouldDeliver, err = e1.relbroadcastInspection(&parsedTsscontent{parsed1, ""}, echo)
			a.NoError(err)
			a.True(shouldBroadcast)
			a.False(shouldDeliver)

			echo.setSource(e1.Self)

			shouldBroadcast, shouldDeliver, err = e1.relbroadcastInspection(&parsedTsscontent{parsed1, ""}, echo)
			a.NoError(err)
			a.False(shouldBroadcast)
			a.True(shouldDeliver)

			echo.setSource(e4.Self)

			shouldBroadcast, shouldDeliver, err = e1.relbroadcastInspection(&parsedTsscontent{parsed1, ""}, echo)
			a.NoError(err)
			a.False(shouldBroadcast)
			a.False(shouldDeliver)
		}
	})
}

func TestUuidNotAffectedByMessageContentChange(t *testing.T) {
	a := assert.New(t)
	engines := load5GuardiansSetupForBroadcastChecks(a)
	e1 := engines[0]
	for i, rnd := range allRounds {
		trackingId := party.Digest{byte(i)}

		// each message is generated with some random content inside.
		parsed1 := generateFakeParsedMessageWithRandomContent(e1.Self, e1.Self, rnd, trackingId)
		parsed2 := generateFakeParsedMessageWithRandomContent(e1.Self, e1.Self, rnd, trackingId)

		uid1, err := parsed1.getUUID(e1.LoadDistributionKey)
		a.NoError(err)

		uid2, err := parsed2.getUUID(e1.LoadDistributionKey)
		a.NoError(err)
		a.Equal(uid1, uid2)
	}
}

func TestEquivocation(t *testing.T) {
	t.Run("inBroadcastLogic", func(t *testing.T) {
		a := assert.New(t)
		engines := load5GuardiansSetupForBroadcastChecks(a)
		e1, e2 := engines[0], engines[1]

		for i, rndType := range allRounds {

			trackingId := party.Digest{byte(i)}

			parsed1 := generateFakeMessageWithRandomContent(e1.Self, e2.Self, rndType, trackingId)

			shouldBroadcast, shouldDeliver, err := e1.relbroadcastInspection(&parsedTsscontent{parsed1, ""}, parsedIntoEcho(a, e2, parsed1))
			a.NoError(err)
			a.True(shouldBroadcast) //should broadcast since e2 is the source of this message.
			a.False(shouldDeliver)

			parsed2 := generateFakeMessageWithRandomContent(e1.Self, e2.Self, rndType, trackingId)

			shouldBroadcast, shouldDeliver, err = e1.relbroadcastInspection(&parsedTsscontent{parsed2, ""}, parsedIntoEcho(a, e2, parsed2))
			a.ErrorAs(err, &ErrEquivicatingGuardian)
			a.False(shouldBroadcast)
			a.False(shouldDeliver)

			equvicatingEchoerMessage := parsedIntoEcho(a, e2, parsed1)
			equvicatingEchoerMessage.
				Content.
				GetEcho().
				Message.
				Content.(*tsscommv1.SignedMessage_TssContent).
				TssContent.
				Payload[0] += 1
			// now echoer is equivicating (change content, but of some seen message):
			_, _, err = e1.relbroadcastInspection(&parsedTsscontent{parsed1, ""}, equvicatingEchoerMessage)
			a.ErrorContains(err, e2.Self.Id)
		}
	})

	t.Run("inUnicast", func(t *testing.T) {
		a := assert.New(t)
		engines := load5GuardiansSetupForBroadcastChecks(a)
		e1, e2 := engines[0], engines[1]

		ctx, cncl := context.WithCancel(supctx)
		defer cncl()

		e1.Start(ctx)
		e2.Start(ctx)

		for i, rndType := range unicastRounds {

			trackingId := party.Digest{byte(i)}

			parsed1 := generateFakeMessageWithRandomContent(e1.Self, e2.Self, rndType, trackingId)
			parsed2 := generateFakeMessageWithRandomContent(e1.Self, e2.Self, rndType, trackingId)

			bts, _, err := parsed1.WireBytes()
			a.NoError(err)

			msg := &IncomingMessage{
				Content: &tsscommv1.PropagatedMessage{
					Message: &tsscommv1.PropagatedMessage_Unicast{
						Unicast: &tsscommv1.Unicast{
							Content: &tsscommv1.TssContent{
								Payload:         bts,
								MsgSerialNumber: 0,
							},
						},
					},
				},
			}

			msg.setSource(e1.Self)

			e2.handleUnicast(msg)

			bts, _, err = parsed2.WireBytes()
			a.NoError(err)

			msg.Content.Message.(*tsscommv1.PropagatedMessage_Unicast).Unicast.Content.Payload = bts
			a.ErrorIs(e2.handleUnicast(msg), ErrEquivicatingGuardian)
		}
	})
}

func TestBadInputs(t *testing.T) {
	a := assert.New(t)
	engines := load5GuardiansSetupForBroadcastChecks(a)
	e1, e2 := engines[0], engines[1]

	ctx, cancel := context.WithTimeout(supctx, time.Minute*1)
	defer cancel()

	e1.Start(ctx) // so it has a logger.

	t.Run("signature", func(t *testing.T) {
		for j, rnd := range allRounds {
			parsed1 := generateFakeMessageWithRandomContent(e1.Self, e1.Self, rnd, party.Digest{byte(j)})
			echo := parsedIntoEcho(a, e1, parsed1)

			echo.setSource(e2.Self)

			echo.toEcho().Message.Signature[0] += 1
			_, _, err := e1.relbroadcastInspection(&parsedTsscontent{parsed1, ""}, echo)
			a.ErrorIs(err, ErrInvalidSignature)

			if rnd == round1Message1 || rnd == round2Message {
				continue
			}

			echo.setSource(e1.Self)
			err = e1.handleIncomingTssMessage(echo)
			a.ErrorIs(err, ErrInvalidSignature)
			e1.HandleIncomingTssMessage(echo) // to ensure we go through some code path, nothing to check really.
		}
	})

	t.Run("incoming message", func(t *testing.T) {
		var tmp *Engine = nil
		// these tests ensure we don't panic on bad inputs.
		// Shouldn't fail or panic.
		tmp.HandleIncomingTssMessage(nil)
		e1.HandleIncomingTssMessage(nil)
		e2.HandleIncomingTssMessage(nil) // e2 hadn't started.

		err := tmp.handleIncomingTssMessage(nil)
		a.ErrorIs(err, errNilIncoming)

		err = e1.handleIncomingTssMessage(&IncomingMessage{})
		a.ErrorIs(err, errNilSource)

		err = e1.handleIncomingTssMessage(&IncomingMessage{Source: partyIdToProto(e2.Self)})
		a.ErrorIs(err, errNeitherBroadcastNorUnicast)

		err = e1.handleIncomingTssMessage(&IncomingMessage{
			Source:  partyIdToProto(e2.Self),
			Content: &tsscommv1.PropagatedMessage{}})
		a.ErrorIs(err, errNeitherBroadcastNorUnicast)

		err = e1.handleIncomingTssMessage(&IncomingMessage{
			Source: partyIdToProto(e2.Self),
			Content: &tsscommv1.PropagatedMessage{
				Message: &tsscommv1.PropagatedMessage_Echo{},
			},
		})
		a.ErrorIs(err, ErrEchoIsNil)

		err = e1.handleIncomingTssMessage(&IncomingMessage{
			Source: partyIdToProto(e2.Self),
			Content: &tsscommv1.PropagatedMessage{
				Message: &tsscommv1.PropagatedMessage_Echo{Echo: &tsscommv1.Echo{}},
			},
		})
		a.ErrorIs(err, ErrSignedMessageIsNil)

		err = e1.handleIncomingTssMessage(&IncomingMessage{
			Source: partyIdToProto(e2.Self),
			Content: &tsscommv1.PropagatedMessage{
				Message: &tsscommv1.PropagatedMessage_Echo{Echo: &tsscommv1.Echo{
					Message: &tsscommv1.SignedMessage{},
				}}},
		})
		a.ErrorIs(err, ErrNilPartyId)

		err = e1.handleIncomingTssMessage(&IncomingMessage{
			Source: partyIdToProto(e2.Self),
			Content: &tsscommv1.PropagatedMessage{
				Message: &tsscommv1.PropagatedMessage_Echo{Echo: &tsscommv1.Echo{
					Message: &tsscommv1.SignedMessage{
						Sender: &tsscommv1.PartyId{},
					},
				}}},
		})
		a.ErrorIs(err, ErrEmptyIDInPID)

		err = e1.handleIncomingTssMessage(&IncomingMessage{
			Source: partyIdToProto(e2.Self),
			Content: &tsscommv1.PropagatedMessage{
				Message: &tsscommv1.PropagatedMessage_Echo{Echo: &tsscommv1.Echo{
					Message: &tsscommv1.SignedMessage{
						Sender: &tsscommv1.PartyId{
							Id:  "a",
							Key: []byte{},
						},
					},
				}}},
		})
		a.ErrorIs(err, ErrEmptyKeyInPID)

		err = e1.handleIncomingTssMessage(&IncomingMessage{Source: partyIdToProto(e2.Self), Content: &tsscommv1.PropagatedMessage{
			Message: &tsscommv1.PropagatedMessage_Echo{Echo: &tsscommv1.Echo{
				Message: &tsscommv1.SignedMessage{
					Sender: partyIdToProto(e2.Self),
				},
			}}},
		})
		a.ErrorIs(err, ErrNoContent)

		err = e1.handleIncomingTssMessage(&IncomingMessage{Source: partyIdToProto(e2.Self), Content: &tsscommv1.PropagatedMessage{
			Message: &tsscommv1.PropagatedMessage_Echo{Echo: &tsscommv1.Echo{
				Message: &tsscommv1.SignedMessage{
					Content: &tsscommv1.SignedMessage_TssContent{
						TssContent: &tsscommv1.TssContent{},
					},
					Sender: partyIdToProto(e2.Self),
				},
			}}},
		})
		a.ErrorIs(err, ErrNilPayload)

		err = e1.handleIncomingTssMessage(&IncomingMessage{Source: partyIdToProto(e2.Self), Content: &tsscommv1.PropagatedMessage{
			Message: &tsscommv1.PropagatedMessage_Echo{Echo: &tsscommv1.Echo{
				Message: &tsscommv1.SignedMessage{
					Content: &tsscommv1.SignedMessage_TssContent{
						TssContent: &tsscommv1.TssContent{
							Payload: []byte{1, 2, 3},
						},
					},
					Sender: partyIdToProto(e2.Self),
				},
			}}},
		})
		a.ErrorIs(err, ErrNoAuthenticationField)

		err = e1.handleIncomingTssMessage(&IncomingMessage{Source: partyIdToProto(e2.Self), Content: &tsscommv1.PropagatedMessage{
			Message: &tsscommv1.PropagatedMessage_Echo{Echo: &tsscommv1.Echo{
				Message: &tsscommv1.SignedMessage{
					Content: &tsscommv1.SignedMessage_TssContent{
						TssContent: &tsscommv1.TssContent{
							Payload: []byte{1, 2, 3},
						},
					},
					Sender:    partyIdToProto(e2.Self),
					Signature: []byte{1, 2, 3},
				},
			}}},
		})
		a.ErrorContains(err, "cannot parse")
	})

	t.Run("Begin signing", func(t *testing.T) {
		var tmp *Engine = nil
		engines2 := load5GuardiansSetupForBroadcastChecks(a)

		a.ErrorIs(tmp.BeginAsyncThresholdSigningProtocol(nil), errNilTssEngine)
		a.ErrorIs(e2.BeginAsyncThresholdSigningProtocol(nil), errTssEngineNotStarted)

		tmp = engines2[1]
		tmp.started.Store(started)

		a.ErrorContains(e1.BeginAsyncThresholdSigningProtocol(make([]byte, 12)), "length is not 32 bytes")

		tmp.fp = nil
		a.ErrorContains(tmp.BeginAsyncThresholdSigningProtocol(nil), "not set up correctly")
	})

	t.Run("fetch certificate", func(t *testing.T) {
		_, err := e1.FetchCertificate(nil)
		a.ErrorIs(err, ErrNilPartyId)

		_, err = e1.FetchCertificate(&tsscommv1.PartyId{})
		a.ErrorContains(err, "not found")
	})
}

func TestFetchPartyId(t *testing.T) {
	a := assert.New(t)
	engines := load5GuardiansSetupForBroadcastChecks(a)
	e1 := engines[0]
	pid, err := e1.FetchPartyId(e1.guardiansCerts[0])
	a.NoError(err)
	a.Equal(e1.Self.Id, pid.Id)

	crt := createX509Cert("localhost")
	_, err = e1.FetchPartyId(crt)
	a.ErrorContains(err, "unsupported") // cert.PublicKey=nil

	crt.PublicKey = []byte{1, 2, 3}
	_, err = e1.FetchPartyId(crt)
	a.ErrorContains(err, "unknown")
}

func TestCleanup(t *testing.T) {
	a := assert.New(t)
	engines := load5GuardiansSetupForBroadcastChecks(a)
	e1 := engines[0]

	uuid1 := uuid{1}
	e1.received[uuid1] = &broadcaststate{
		timeReceived: time.Now().Add(time.Minute * 10 * (-1)),
		trackingId: &tsscommon.TrackingID{
			Digest: uuid1[:],
		},
	}

	uuid2 := uuid{2}
	e1.received[uuid2] = &broadcaststate{
		timeReceived: time.Now(),
		trackingId: &tsscommon.TrackingID{
			Digest: uuid2[:],
		},
	}

	e1.cleanup(time.Minute * 5) // if more than 5 minutes passed -> delete
	a.Len(e1.received, 1)
	_, ok := e1.received[uuid{1}]
	a.False(ok)

	_, ok = e1.received[uuid{2}]
	a.True(ok)
}

type badtssMessage struct {
}

func (b *badtssMessage) GetFrom() *tss.PartyID         { panic("unimplemented") }
func (b *badtssMessage) GetTo() []*tss.PartyID         { panic("unimplemented") }
func (b *badtssMessage) IsBroadcast() bool             { panic("unimplemented") }
func (b *badtssMessage) IsToOldAndNewCommittees() bool { panic("unimplemented") }
func (b *badtssMessage) IsToOldCommittee() bool        { panic("unimplemented") }
func (b *badtssMessage) String() string                { panic("unimplemented") }
func (b *badtssMessage) Type() string                  { panic("unimplemented") }
func (b *badtssMessage) WireMsg() *tss.MessageWrapper {
	return &tss.MessageWrapper{
		TrackingID: nil,
	}
}
func (b *badtssMessage) WireBytes() ([]byte, *tss.MessageRouting, error) {
	return nil, nil, errors.New("bad message")
}

func TestRouteCheck(t *testing.T) {
	// this test is a bit of a hack.
	// To ensure we don't panic on bad inputs.
	a := assert.New(t)
	engines := load5GuardiansSetupForBroadcastChecks(a)
	e1 := engines[0]

	ctx, cancel := context.WithTimeout(supctx, time.Second*5)
	defer cancel()

	e1.Start(ctx)
	e1.fpOutChan <- &badtssMessage{}
	e1.fpErrChannel <- tss.NewTrackableError(errors.New("test"), "test", -1, nil, &tsscommon.TrackingID{})
	e1.fpErrChannel <- nil

	time.Sleep(time.Millisecond * 200)

}

func TestE2E(t *testing.T) {
	// Setting up all engines (not just 5), each with a different guardian storage.
	// all will attempt to sign a single message, while outputing messages to each other,
	// and reliably broadcasting them.

	t.Run("with correct metrics", func(t *testing.T) {
		inProgressSigs.Set(0) // reseting the gauge.

		a := assert.New(t)
		engines := loadGuardians(a)

		dgst := party.Digest{1, 2, 3, 4, 5, 6, 7, 8, 9}

		ctx, cancel := context.WithTimeout(supctx, time.Minute*1)
		defer cancel()

		fmt.Println("starting engines.")
		for _, engine := range engines {
			a.NoError(engine.Start(ctx))
		}

		fmt.Println("msgHandler settup:")
		dnchn := msgHandler(ctx, engines, 1)

		fmt.Println("engines started, requesting sigs")

		m := dto.Metric{}
		inProgressSigs.Write(&m)
		a.Equal(0, int(m.Gauge.GetValue()))

		// all engines are started, now we can begin the protocol.
		for _, engine := range engines {
			tmp := make([]byte, 32)
			copy(tmp, dgst[:])
			engine.BeginAsyncThresholdSigningProtocol(tmp)
		}

		inProgressSigs.Write(&m)
		a.Equal(engines[0].Threshold+1, int(m.Gauge.GetValue()))

		if ctxExpiredFirst(ctx, dnchn) {
			a.FailNowf("%s", "context expired")
		}

		time.Sleep(time.Millisecond * 500) // ensuring all other engines have finished and not just one of them.
		inProgressSigs.Write(&m)
		a.Equal(0, int(m.Gauge.GetValue())) // ensuring nothing is in progress.

		sigProducedCntr.Write(&m)
		a.Equal(engines[0].Threshold+1, int(m.Counter.GetValue()))

		sentMsgCntr.Write(&m)
		committeeSize := engines[0].Threshold + 1
		numBroadcastRounds := 8
		numUnicastRounds := 2
		numUnicastSendRequestsPerGuardian := engines[0].Threshold * numUnicastRounds
		a.Equal(committeeSize*(numBroadcastRounds+numUnicastSendRequestsPerGuardian), int(m.Counter.GetValue()))

		receivedMsgCntr.Write(&m)
		// n^2 * (numBroadcastRounds + numUnicastRounds)
		a.Greater(int(m.Counter.GetValue()), committeeSize*committeeSize*(numBroadcastRounds+numUnicastRounds))

		deliveredMsgCntr.Write(&m)
		// messages from committeeSize are delivered numBroadcastRounds times by each guardian.
		a.Equal(committeeSize*numBroadcastRounds*len(engines), int(m.Counter.GetValue()))
	})

	t.Run("with 5 sigs", func(t *testing.T) {
		a := assert.New(t)
		engines := loadGuardians(a)

		digests := make([]party.Digest, 5)
		for i := 0; i < 5; i++ {
			digests[i] = party.Digest{byte(i)}
		}

		ctx, cancel := context.WithTimeout(supctx, time.Minute*1)
		defer cancel()

		fmt.Println("starting engines.")
		for _, engine := range engines {
			a.NoError(engine.Start(ctx))
		}

		fmt.Println("msgHandler settup:")
		dnchn := msgHandler(ctx, engines, len(digests))

		fmt.Println("engines started, requesting sigs")

		// all engines are started, now we can begin the protocol.
		for _, d := range digests {

			for _, engine := range engines {
				tmp := make([]byte, 32)
				copy(tmp, d[:])

				engine.BeginAsyncThresholdSigningProtocol(tmp)
			}
		}

		if ctxExpiredFirst(ctx, dnchn) {
			a.FailNowf("%s", "context expired")
		}
	})
}

func ctxExpiredFirst(ctx context.Context, ch chan struct{}) bool {
	select {
	case <-ctx.Done():
		return true
	case <-ch:
		return false
	}
}

func TestFT(t *testing.T) {
	// t.FailNow()
	// return
	t.Run("single failing server", func(t *testing.T) {
		a := assert.New(t)

		ctx, cancel := context.WithTimeout(supctx, time.Minute*1)
		defer cancel()

		dgst := party.Digest{1, 2, 3, 4, 5, 6, 7, 8, 9}

		engines := loadGuardians(a)
		fmt.Println("starting engines.")
		for _, engine := range engines {
			a.NoError(engine.Start(ctx))
		}

		fmt.Println("msgHandler settup:")
		dnchn := msgHandler(ctx, engines, 1)

		fmt.Println("engines started, requesting sigs")

		e := getSigningGuardian(a, engines, digest(dgst))

		enginesWithoutE := make([]*Engine, 0, len(engines)-1)
		eSelf := partyIdToString(e.Self)
		for i := range engines {
			if partyIdToString(engines[i].Self) == eSelf {
				continue
			}

			enginesWithoutE = append(enginesWithoutE, engines[i])
		}

		// all engines are started, now we can begin the protocol.
		for _, engine := range enginesWithoutE {
			tmp := make([]byte, 32)
			copy(tmp, dgst[:])
			engine.BeginAsyncThresholdSigningProtocol(tmp)
		}

		if ctxExpiredFirst(ctx, dnchn) {
			a.FailNowf("%s", "context expired")
		}
	})

	t.Run("downserver returns and signs on original committee", func(t *testing.T) {
		a := assert.New(t)

		ctx, cancel := context.WithTimeout(supctx, time.Minute*1)
		defer cancel()

		dgst := party.Digest{1, 2, 3, 4, 5, 6, 7, 8, 9}

		engines := loadGuardians(a)
		for _, e := range engines {
			e.GuardianStorage.Configurations.GuardianSigningDownTime = time.Second * 10
		}

		signers := getSigningGuardians(a, engines, digest(dgst))

		fmt.Println("starting engines.")
		for _, engine := range signers { // start only original committee!
			a.NoError(engine.Start(ctx))
		}

		fmt.Println("msgHandler settup:")
		dnchn := msgHandler(ctx, engines, 1)

		fmt.Println("engines started, requesting sigs")

		signers[0].reportProblem(0) // using chainid==0.

		time.Sleep(time.Second * 2)

		// Only engines from original comittee are allowed to sign.
		for _, engine := range signers {
			tmp := make([]byte, 32)
			copy(tmp, dgst[:])

			engine.BeginAsyncThresholdSigningProtocol(tmp)
		}

		if ctxExpiredFirst(ctx, dnchn) {
			a.FailNowf("%s", "context expired")
		}
	})

	t.Run("1 sig 2 faults one after the other", func(t *testing.T) {
		// set a scenario where one of the original doesn't receive the OK to sign, and a server in the next committee is
		// doesn't receive the OK to sign also.
		t.Fail()
	})

	t.Run("3 sigs and 3 faults", func(t *testing.T) {
		t.Fail()
	})

}

func TestMessagesWithBadRounds(t *testing.T) {
	a := assert.New(t)
	gs := load5GuardiansSetupForBroadcastChecks(a)
	e1, e2 := gs[0], gs[1]
	from := e1.Self
	to := e2.Self

	t.Run("Unicast", func(t *testing.T) {
		msgDigest := party.Digest{1}
		for _, rnd := range broadcastRounds {
			parsed := generateFakeMessageWithRandomContent(from, to, rnd, msgDigest)
			bts, _, err := parsed.WireBytes()
			a.NoError(err)

			m := &IncomingMessage{
				Source: partyIdToProto(from),
				Content: &tsscommv1.PropagatedMessage{Message: &tsscommv1.PropagatedMessage_Unicast{
					Unicast: &tsscommv1.Unicast{
						Content: &tsscommv1.TssContent{Payload: bts},
					},
				}},
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

			m := &IncomingMessage{
				Source: partyIdToProto(from),
				Content: &tsscommv1.PropagatedMessage{Message: &tsscommv1.PropagatedMessage_Echo{
					Echo: &tsscommv1.Echo{
						Message: &tsscommv1.SignedMessage{
							Content: &tsscommv1.SignedMessage_TssContent{
								TssContent: &tsscommv1.TssContent{Payload: bts},
							},
							Sender:    partyIdToProto(from),
							Signature: nil,
						},
					},
				}},
			}
			a.NoError(e1.sign(m.Content.GetEcho().Message))

			_, err = e2.handleEcho(m)
			a.ErrorIs(err, errBadRoundsInEcho)
		}
	})
}

func generateFakeParsedMessageWithRandomContent(from, to *tss.PartyID, rnd signingRound, digest party.Digest) parsedMsg {
	fake := generateFakeMessageWithRandomContent(from, to, rnd, digest)
	return &parsedTsscontent{fake, ""}
}

// if to == nil it's a broadcast message.
func generateFakeMessageWithRandomContent(from, to *tss.PartyID, rnd signingRound, digest party.Digest) tss.ParsedMessage {
	partiesState := make([]byte, maxParties)
	for i := 0; i < maxParties; i++ {
		partiesState[i] = 255
	}

	trackingId := &tsscommon.TrackingID{
		Digest:       digest[:],
		PartiesState: partiesState,
		AuxilaryData: []byte{},
	}

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

	return tss.NewMessage(meta, content, tss.NewMessageWrapper(meta, content, trackingId))
}

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

func _loadGuardians(numParticipants int) ([]*Engine, error) {
	engines := make([]*Engine, numParticipants)

	for i := 0; i < numParticipants; i++ {
		e, err := NewReliableTSS(loadMockGuardianStorage(i))
		if err != nil {
			return nil, err
		}
		en, ok := e.(*Engine)
		if !ok {
			return nil, errors.New("not an engine")
		}
		engines[i] = en
	}

	return engines, nil
}

func loadGuardians(a *assert.Assertions) []*Engine {
	engines, err := _loadGuardians(Participants)
	a.NoError(err)

	return engines
}

type msgg struct {
	Sender *tsscommv1.PartyId
	Sendable
}

func msgHandler(ctx context.Context, engines []*Engine, numDiffSigsExpected int) chan struct{} {
	signalSuccess := make(chan struct{})
	once := sync.Once{}

	go func() {
		wg := sync.WaitGroup{}
		wg.Add(len(engines) * 2)

		chns := make(map[string]chan msgg, len(engines))
		for _, en := range engines {
			chns[en.Self.Id] = make(chan msgg, 10000)
		}

		for _, e := range engines {
			engine := e

			// need a separate goroutine for handling engine output and engine input.
			// simulating network stream incoming and network stream outgoing.

			// incoming
			go func() {
				defer wg.Done()
				for {
					select {
					case <-ctx.Done():
						return

					case msg := <-chns[engine.Self.Id]:
						engine.HandleIncomingTssMessage(&IncomingMessage{
							Source:  msg.Sender,
							Content: msg.GetNetworkMessage(),
						})
					}
				}
			}()

			//  Listener, responsible to receive output of engine, and direct it to the other engines.
			go func() {
				nmsigs := map[digest]struct{}{}
				defer wg.Done()
				for {
					select {
					case <-ctx.Done():
						return

					case m := <-engine.ProducedOutputMessages():
						if m.IsBroadcast() {
							broadcast(chns, engine, m)
							continue
						}
						unicast(m, chns, engine)
					case sig := <-engine.ProducedSignature():
						signature := append(sig.Signature, sig.SignatureRecovery...)
						address := engine.GetEthAddress()

						pubKey, err := crypto.Ecrecover(sig.M, signature)
						if err != nil {
							panic("failed to do ecrecover:" + err.Error())
						}
						addr := common.BytesToAddress(crypto.Keccak256(pubKey[1:])[12:])

						// check that the recovered address equals the provided address
						if addr != address {
							panic("recovered address does not match provided address")
						}
						nmsigs[digest(sig.TrackingId.Digest)] = struct{}{}

						if len(nmsigs) < numDiffSigsExpected {
							continue
						}

						once.Do(func() {
							close(signalSuccess)
						})
					}
				}
			}()
		}

		wg.Wait()
	}()

	return signalSuccess
}

func unicast(m Sendable, chns map[string]chan msgg, engine *Engine) {
	pids := m.GetDestinations()
	for _, pid := range pids {
		feedChn := chns[pid.Id]
		feedChn <- msgg{
			Sender:   partyIdToProto(engine.Self),
			Sendable: m.cloneSelf(),
		}
	}
}

func broadcast(chns map[string]chan msgg, engine *Engine, m Sendable) {
	for _, feedChn := range chns {
		feedChn <- msgg{
			Sender:   partyIdToProto(engine.Self),
			Sendable: m.cloneSelf(),
		}
	}
}

// strictly for the tests.
func (c *activeSigCounter) digestToGuardiansLen() int {
	c.mtx.RLock()
	defer c.mtx.RUnlock()

	return len(c.digestToGuardians)
}

func TestSigCounter(t *testing.T) {
	a := assert.New(t)

	ctx, cancel := context.WithTimeout(supctx, time.Minute*1)
	defer cancel()

	t.Run("MaxCountBlockAdditionalUpdates", func(t *testing.T) {
		// Tests might fail due to change of the GuardianStorage files
		digests := []digest{{1}, {2}}
		engines := load5GuardiansSetupForBroadcastChecks(a)
		e1 := getSigningGuardian(a, engines, digests...)

		e1.MaxSimultaneousSignatures = 1
		e1.Start(ctx)

		msg := beginSigningAndGrabMessage(e1, digests[0])

		a.NoError(e1.handleIncomingTssMessage(&IncomingMessage{
			Source:  partyIdToProto(e1.Self),
			Content: msg.GetNetworkMessage(),
		}))

		// trying to handle a new message for a different signature.
		msg = beginSigningAndGrabMessage(e1, digests[1])

		a.ErrorContains(e1.handleIncomingTssMessage(&IncomingMessage{
			Source:  partyIdToProto(e1.Self),
			Content: msg.GetNetworkMessage(),
		}), "reached the maximum number of simultaneous signatures")
	})

	t.Run("ErrorReduceCount", func(t *testing.T) {
		// Tests might fail due to change of the GuardianStorage files
		digests := []digest{{1}}
		engines := load5GuardiansSetupForBroadcastChecks(a)
		e1 := getSigningGuardian(a, engines, digests...)
		e1.MaxSimultaneousSignatures = 1

		e1.Start(ctx)

		msg := beginSigningAndGrabMessage(e1, digests[0])

		incoming := &IncomingMessage{
			Source:  partyIdToProto(e1.Self),
			Content: msg.GetNetworkMessage(),
		}

		a.NoError(e1.handleIncomingTssMessage(incoming))

		parsed, err := e1.parseUnicast(incoming)
		a.NoError(err)

		// test:
		a.Equal(e1.sigCounter.digestToGuardiansLen(), 1)
		select {
		case e1.fpErrChannel <- tss.NewTrackableError(fmt.Errorf("dummyerr"), "de", -1, e1.Self, parsed.getTrackingID()):
		case <-time.After(time.Second * 1):
			t.FailNow()
			return
		}

		time.Sleep(time.Millisecond * 500)

		a.Equal(e1.sigCounter.digestToGuardiansLen(), 0)
	})

	t.Run("sigDoneReduceCount", func(t *testing.T) {
		// Tests might fail due to change of the GuardianStorage files
		digests := []digest{{1}}
		engines := load5GuardiansSetupForBroadcastChecks(a)
		e1 := getSigningGuardian(a, engines, digests...)
		e1.MaxSimultaneousSignatures = 1

		e1.Start(ctx)

		msg := beginSigningAndGrabMessage(e1, digests[0])

		incoming := &IncomingMessage{
			Source:  partyIdToProto(e1.Self),
			Content: msg.GetNetworkMessage(),
		}

		a.NoError(e1.handleIncomingTssMessage(incoming))

		parsed, err := e1.parseUnicast(incoming)
		a.NoError(err)

		// test:
		a.Equal(e1.sigCounter.digestToGuardiansLen(), 1)
		e1.fpSigOutChan <- &tsscommon.SignatureData{
			Signature:         []byte{},
			SignatureRecovery: []byte{},
			R:                 []byte{},
			S:                 []byte{},
			M:                 []byte{},
			TrackingId:        parsed.getTrackingID(),
		}
		time.Sleep(time.Millisecond * 500)
		a.Equal(e1.sigCounter.digestToGuardiansLen(), 0)
	})

	t.Run("CanHaveSimulSigners", func(t *testing.T) {
		digests := []digest{{1}, {2}}
		engines := load5GuardiansSetupForBroadcastChecks(a)
		e1 := getSigningGuardian(a, engines, digests...)
		e1.MaxSimultaneousSignatures = 2

		e1.Start(ctx)

		msg := beginSigningAndGrabMessage(e1, digests[0])

		a.NoError(e1.handleIncomingTssMessage(&IncomingMessage{
			Source:  partyIdToProto(e1.Self),
			Content: msg.GetNetworkMessage(),
		}))

		a.NoError(e1.handleIncomingTssMessage(&IncomingMessage{
			Source:  partyIdToProto(e1.Self),
			Content: beginSigningAndGrabMessage(e1, digests[1]).GetNetworkMessage(),
		}))

	})
}
func getSigningGuardian(a *assert.Assertions, engines []*Engine, digests ...digest) *Engine {
	return getSigningGuardians(a, engines, digests...)[0]
}

func getSigningGuardians(a *assert.Assertions, engines []*Engine, digests ...digest) []*Engine {
	a.GreaterOrEqual(len(digests), 1) // at least one

	guardians := make([]*Engine, 0, len(engines))
mainloop:
	for _, e := range engines {

		for _, d := range digests {
			st := party.SigningTask{}
			copy(st.Digest[:], d[:])

			info1, err := e.fp.GetSigningInfo(st)
			a.NoError(err)

			if !info1.IsSigner {
				continue mainloop
			}
		}

		guardians = append(guardians, e)
	}

	return guardians
}

func beginSigningAndGrabMessage(e1 *Engine, d digest) Sendable {
	go e1.BeginAsyncThresholdSigningProtocol(d[:])

	var msg Sendable
	for i := 0; i < round1NumberOfMessages(e1); i++ { // cleaning the channel, and taking one of the messages.
		select {
		case tmp := <-e1.ProducedOutputMessages():
			if !tmp.IsBroadcast() {
				msg = tmp
			}

		case <-time.After(time.Second * 5):
			// This means the signer wasn't one of the signing committees. (did the Guardian storage change?)
			// if it did, just make sure this engine is expected to sign, else use the right engine in the test.
			panic("timeout!")
		}
	}
	return msg
}

func round1NumberOfMessages(e1 *Engine) int {
	// although threshold is non-inclusive, we only send e1.Threshold since one doesn't includes itself in the unicasts.
	// the +1 is for the additional broadcast message.
	return e1.Threshold + 1
}
