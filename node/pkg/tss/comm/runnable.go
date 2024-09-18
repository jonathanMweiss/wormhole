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
	TssEngine tss.MessageReceiver

	// PartyId.ID  == hostname.
	// partyId.Key == self signed certificate.
	// Moniker can be anything.
	// Index doesn't matter for this service.
	Peers []tsscommv1.PartyId
}

func NewServer(params *Parameters) (DirectLink, error) {
	if err := validateParams(params); err != nil {
		return nil, err
	}

	laddr, err := net.ResolveUnixAddr("unix", params.SocketPath)
	if err != nil {
		return nil, fmt.Errorf("invalid listen address: %v", err)
	}

	l, err := net.ListenUnix("unix", laddr)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on %s: %w", params.SocketPath, err)
	}

	gserver := grpc.NewServer(
	// TODO set credentials and known CA.
	// TODO: set CA as pool of certs of the guardians. each guardian is its own CA, and we know all of them.
	)

	conns := make(map[string]*connection, len(params.Peers))
	for _, pid := range params.Peers {
		conns[pid.Id] = &connection{
			cc:     nil,
			stream: nil,
		}
	}

	s := &server{
		UnimplementedDirectLinkServer: tsscommv1.UnimplementedDirectLinkServer{},
		ctx:                           nil, // to be set in Run(ctx context.Context).
		params:                        params,

		connections: conns,

		gserver:  gserver,
		listener: l,
	}

	tsscommv1.RegisterDirectLinkServer(gserver, s)

	return s, nil
}

func validateParams(params *Parameters) error {
	return nil // TODO.
}

// Run initialise the server and starts listening on the socket.
// In addition, it will set up connections to all given peers (guardians).
func (s *server) Run(ctx context.Context) error {
	if s == nil {
		return fmt.Errorf("tsscomm.server is nil")
	}

	s.ctx = ctx
	s.params.Logger.Info("admin server listening on", zap.String("path", s.params.SocketPath))

	errC := make(chan error)
	go func() { errC <- s.gserver.Serve(s.listener) }()

	s.establishConnections(errC)

	var err error
	select {
	case <-ctx.Done():
		err = ctx.Err()
	case err = <-errC:
	}

	s.gserver.Stop()

	return err
}
