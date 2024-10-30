package tss

import (
	"crypto/ecdsa"
	"sync"
	"time"

	"github.com/certusone/wormhole/node/pkg/tss/internal"
	ethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	tssutil "github.com/yossigi/tss-lib/v2/ecdsa/ethereum"
	"github.com/yossigi/tss-lib/v2/ecdsa/party"
	"github.com/yossigi/tss-lib/v2/tss"
)

type trackidStr string

// ftInvestigator is responsible for tracking the state of signatures, and whether some guardian is not participating in the protocol.
type ftFullParty struct {
	sigStates map[trackidStr]*signatureState
	ttlheap   internal.Ttlheap[*signatureState]

	// used by the follower to inform the FP with changes required.
	party.FullParty
}

func newFtFullParty(fp party.FullParty) *ftFullParty {
	return &ftFullParty{
		sigStates: make(map[trackidStr]*signatureState),
		ttlheap:   internal.NewTtlHeap[*signatureState](),
		FullParty: fp,
	}
}

func (f *ftFullParty) isSet() bool {
	return f != nil && f.FullParty != nil && f.sigStates != nil && f.ttlheap != nil
}

func (f *ftFullParty) GetPublicKey() *ecdsa.PublicKey {
	return f.FullParty.GetPublic()
}

func (f *ftFullParty) GetEthAddress() ethcommon.Address {
	pubkey := f.FullParty.GetPublic()
	ethAddBytes := ethcommon.LeftPadBytes(
		crypto.Keccak256(tssutil.EcdsaPublicKeyToBytes(pubkey)[1:])[12:], 32)

	return ethcommon.BytesToAddress(ethAddBytes)
}

func (f *ftFullParty) NewSignature(d party.Digest) error {
	err := f.FullParty.AsyncRequestNewSignature(d)
	// TODO: start following this signature state!

	if err == party.ErrNotInSigningCommittee { // no need to return error in this case.
		return nil
	}

	// TODO: we might need another gauge counter: allSigsInProgress (not affected by ErrNotInSigningCommittee)
	inProgressSigs.Inc()

	return nil
}

// this signature structs are held by two different data structures.
// 1. a map so we can access and update these easily.
// 2. a heap to keep track of the ttl of each signature.
//
// Once the timer of the heap pops, we checkw whether rounds advanced since last ttl update, if so, insert back to heap with new ttl.
// if not, tell the FP to change the committee (remove the guardian that didn't manage to deliver the message).
type signatureState struct {
	mtx     sync.Mutex
	trackid []byte

	signingCommittee []*tss.PartyID

	// updated before feeding the FP with this value.
	delivered    [numBroadcastsPerSignature][]*tss.PartyID
	sawUnicasts  [numUnicastsRounds][]*tss.PartyID // TODO.
	currentRound int                               // starts with 1 and advances to 9.

	EndTime time.Time // set x seconds, once timer pops, check if advanced to next round.
	// if something wasn't delivered from some guardian -> Remove this guardian from committee.
	// For each round advanced: add x seconds to ttl.
}

// GetEndTime is in capital to support the HasTTl interface.
func (s *signatureState) GetEndTime() time.Time {
	s.mtx.Lock()
	endtime := s.EndTime
	s.mtx.Unlock()

	return endtime
}

func (s *signatureState) addToEndTime(t time.Duration) {
	s.mtx.Lock()
	s.EndTime = s.EndTime.Add(t)
	s.mtx.Unlock()
}
