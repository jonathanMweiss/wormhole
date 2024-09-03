package tss

import (
	"math/big"
	"testing"

	"github.com/certusone/wormhole/node/pkg/internal/testutils"
	gossipv1 "github.com/certusone/wormhole/node/pkg/proto/gossip/v1"
	"github.com/stretchr/testify/assert"
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

	t.Run("forEnoughEchoesButBroadcastOnlyOnce", func(t *testing.T) {
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
