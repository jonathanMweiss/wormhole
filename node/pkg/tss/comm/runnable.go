package comm

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"

	tsscommv1 "github.com/certusone/wormhole/node/pkg/proto/tsscomm/v1"
	"github.com/certusone/wormhole/node/pkg/tss"
	"go.uber.org/zap"
	"google.golang.org/grpc"
)

type DirectLink interface {
	tsscommv1.DirectLinkServer

	Run(context.Context) error
}

type Parameters struct {
	SocketPath      string
	SelfCredentials tls.Certificate

	Logger    *zap.Logger
	TssEngine tss.ReliableMessageHandler

	// PartyId.ID  == hostname.
	// partyId.Key == self signed certificate.
	// Moniker can be anything.
	// Index doesn't matter for this service.
	Peers []*tsscommv1.PartyId
}

func NewServer(params *Parameters) DirectLink {
	return &server{
		UnimplementedDirectLinkServer: tsscommv1.UnimplementedDirectLinkServer{},
		ctx:                           nil, // set up in Run(ctx)

		params:      params,
		connections: make(map[string]*connection, len(params.Peers)),

		requestRedial: make(chan string, len(params.Peers)),
		redials:       make(chan redialResponse, 1),
	}
}

// Run initialise the server and starts listening on the socket.
// In addition, it will set up connections to all given peers (guardians).
func (s *server) Run(ctx context.Context) error {
	if s == nil {
		return fmt.Errorf("tsscomm.server is nil")
	}

	s.ctx = ctx

	listener, err := net.Listen("tcp", s.params.SocketPath)
	if err != nil {
		return err
	}

	errC := make(chan error)
	gserver := grpc.NewServer(
	// TODO set credentials
	// TODO: set CA as pool of certs of the guardians. each guardian is its own CA, and we know all of them.
	)

	tsscommv1.RegisterDirectLinkServer(gserver, s)

	go func() {
		errC <- gserver.Serve(listener)
	}()
	s.run()

	s.params.Logger.Info("admin server listening on", zap.String("path", s.params.SocketPath))

	select {
	case <-ctx.Done():
		err = ctx.Err()
	case err = <-errC:
	}

	gserver.Stop()
	// TODO consider how to address this errors:
	listener.Close()

	return err
}
