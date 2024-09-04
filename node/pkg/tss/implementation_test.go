package tss

import (
	"context"
	"fmt"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/certusone/wormhole/node/pkg/internal/testutils"
	gossipv1 "github.com/certusone/wormhole/node/pkg/proto/gossip/v1"
	"github.com/stretchr/testify/assert"
	"github.com/yossigi/tss-lib/v2/ecdsa/party"
	"github.com/yossigi/tss-lib/v2/ecdsa/signing"
	"github.com/yossigi/tss-lib/v2/tss"
)

func loadMockGuardianStorage(gstorageIndex int) *GuardianStorage {
	path, err := testutils.GetMockGuardianTssStorage(gstorageIndex)
	if err != nil {
		panic(err)
	}

	st, err := GuardianStorageFromFile(path)
	if err != nil {
		panic(err)
	}
	return st
}

func parsedIntoEcho(a *assert.Assertions, t *Engine, parsed tss.ParsedMessage) *gossipv1.Echo {
	payload, _, err := parsed.WireBytes()
	a.NoError(err)

	echo1 := &gossipv1.Echo{
		Message: &gossipv1.SignedMessage{
			Payload:         payload,
			Sender:          partyIdToProto(t.Self),
			Recipients:      nil,
			MsgSerialNumber: 0,
			Authentication:  nil,
		},
		Signature: []byte{},
		Echoer:    &gossipv1.PartyId{},
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
		parsed1 := signing.NewSignRound3Message(e1.Self, big.NewInt(0), big.NewInt(0))

		shouldBroadcast, shouldDeliver, err := e1.relbroadcastInspection(parsed1, parsedIntoEcho(a, e1, parsed1))
		a.NoError(err)
		a.True(shouldBroadcast)
		a.False(shouldDeliver)
	})

	t.Run("forEnoughEchos", func(t *testing.T) {
		a := assert.New(t)
		engines := loadGuardians(a)
		e1, e2, e3 := engines[0], engines[1], engines[2]

		// two different signers on an echo, meaning it will receive from two players.
		// since f=1 and we have f+1 echos: it should broadcast at the end of this test.
		parsed1 := signing.NewSignRound3Message(e1.Self, big.NewInt(0), big.NewInt(0))

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
	})
}

func TestDeliver(t *testing.T) {
	t.Run("After2fPlus1Messages", func(t *testing.T) {
		a := assert.New(t)
		engines := loadGuardians(a)
		e1, e2, e3 := engines[0], engines[1], engines[2]

		// two different signers on an echo, meaning it will receive from two players.
		// since f=1 and we have f+1 echos: it should broadcast at the end of this test.
		parsed1 := signing.NewSignRound3Message(e1.Self, big.NewInt(0), big.NewInt(0))

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
	})

	t.Run("doesn'tDeliverTwice", func(t *testing.T) {
		a := assert.New(t)
		engines := loadGuardians(a)
		e1, e2, e3, e4 := engines[0], engines[1], engines[2], engines[3]

		// two different signers on an echo, meaning it will receive from two players.
		// since f=1 and we have f+1 echos: it should broadcast at the end of this test.
		parsed1 := signing.NewSignRound3Message(e1.Self, big.NewInt(0), big.NewInt(0))

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
	})
}

func TestUuidNotAffectedByMessageContentChange(t *testing.T) {
	a := assert.New(t)
	engines := loadGuardians(a)
	e1 := engines[0]

	// this is used as session ID, and was added by us specifically to each message, to ensure two sessions differ.
	// Changing this, is like looking at a whole different session, where signature is required over another message.
	OriginalMessageDigest := big.NewInt(0)
	uid1, err := e1.getMessageUUID(signing.NewSignRound3Message(e1.Self, big.NewInt(0), OriginalMessageDigest))
	a.NoError(err)

	uid2, err := e1.getMessageUUID(signing.NewSignRound3Message(e1.Self, big.NewInt(1), OriginalMessageDigest))
	a.NoError(err)
	a.Equal(uid1, uid2)
}

func TestEquivocation(t *testing.T) {
	t.Run("inBroadcastLogic", func(t *testing.T) {
		a := assert.New(t)
		engines := loadGuardians(a)
		e1, e2 := engines[0], engines[1]

		// two different signers on an echo, meaning it will receive from two players.
		// since f=1 and we have f+1 echos: it should broadcast at the end of this test.

		// this is used as session ID, and was added by us specifically to each message, to ensure two sessions differ.
		// Changing this, is like looking at a whole different session, where signature is required over another message.
		OriginalMessageDigest := big.NewInt(0)

		parsed1 := signing.NewSignRound3Message(e2.Self, big.NewInt(0), OriginalMessageDigest)

		shouldBroadcast, shouldDeliver, err := e1.relbroadcastInspection(parsed1, parsedIntoEcho(a, e2, parsed1))
		a.NoError(err)
		a.True(shouldBroadcast) //should broadcast since e2 is the source of this message.
		a.False(shouldDeliver)

		// same digest, different message (same signature session, different message)
		parsed2 := signing.NewSignRound3Message(e2.Self, big.NewInt(1), OriginalMessageDigest)

		shouldBroadcast, shouldDeliver, err = e1.relbroadcastInspection(parsed2, parsedIntoEcho(a, e2, parsed2))
		a.ErrorAs(err, &ErrEquivicatingGuardian)
		a.False(shouldBroadcast)
		a.False(shouldDeliver)
	})
}

func TestE2E(t *testing.T) {
	// Setting up 5 engines, each with a different guardian storage.
	// all will attempt to sign a single message, while outputing messages to each other,
	// and reliably broadcasting them.

	a := assert.New(t)
	engines := loadGuardians(a)

	dgst := party.Digest{1, 2, 3, 4, 5, 6, 7, 8, 9}

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute*60)
	defer cancel() // ensures all engines will stop (avoid dangling goroutines).

	fmt.Println("starting engines.")
	for _, engine := range engines {
		a.NoError(engine.Start(ctx))
	}

	fmt.Println("msgHandler settup:")
	dnchn := msgHandler(a, ctx, engines)

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

func loadGuardians(a *assert.Assertions) []*Engine {
	engines := make([]*Engine, Participants)

	for i := 0; i < Participants; i++ {
		e, err := NewReliableTSS(loadMockGuardianStorage(i))
		a.NoError(err)
		engines[i] = e
	}

	return engines
}

func msgHandler(a *assert.Assertions, ctx context.Context, engines []*Engine) chan struct{} {
	signalSuccess := make(chan struct{})
	once := sync.Once{}

	go func() {
		wg := sync.WaitGroup{}
		wg.Add(len(engines) * 2)

		chns := make([]chan *gossipv1.GossipMessage_TssMessage, len(engines))
		for i := range chns {
			chns[i] = make(chan *gossipv1.GossipMessage_TssMessage, 10000)
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
							feedChn <- m.Message.(*gossipv1.GossipMessage_TssMessage)
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
