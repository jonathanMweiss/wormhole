package tss

import (
	"time"

	"github.com/yossigi/tss-lib/v2/ecdsa/party"
)

const (
	digestSize = 32

	notStarted uint32 = 0 // using 0 since it's the default value
	started    uint32 = 1

	// byte sizes
	hostnameSize     = 255
	pemKeySize       = 178
	signingRoundSize = 8

	// auxiliaryData is emmiterchain + chainID in bytes.
	auxiliaryDataSize = 4 + 4
	maxParties        = 256
	// trackindID = digest + auxiliaryData + bitmap of all parties
	// 3 bytes for '-' between each field.
	trackingIDSize = party.DigestSize + (maxParties / 8) + auxiliaryDataSize + 3

	defaultMaxLiveSignatures = 1000

	defaultMaxSignerTTL            = time.Minute * 5
	defaultMaxSigStartWaitTime     = time.Second * 10
	defaultGuardianSigningDownTime = time.Second * 10

	numBroadcastsPerSignature = 8 // GG18
	numUnicastsRounds         = 2 // GG18
)
