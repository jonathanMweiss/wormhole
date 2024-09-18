package comm

import (
	"context"
	"crypto/tls"
	"testing"

	"github.com/certusone/wormhole/node/pkg/internal/testutils"
	tsscommv1 "github.com/certusone/wormhole/node/pkg/proto/tsscomm/v1"
	"github.com/certusone/wormhole/node/pkg/supervisor"
	"github.com/stretchr/testify/require"
)

type mockTssMessageHandler struct {
}

func TestSetup(t *testing.T) {
	a := require.New(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx = testutils.MakeSupervisorContext(ctx)

	srvr, err := NewServer(&Parameters{
		SocketPath:      "localhost:5930",
		SelfCredentials: tls.Certificate{},
		Logger:          supervisor.Logger(ctx),
		TssEngine:       nil,
		Peers:           []*tsscommv1.PartyId{},
	})
	a.NoError(err)
	_ = srvr

}
