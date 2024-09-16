package comm

import (
	"context"
	"crypto/tls"
	"crypto/x509"
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
	CA              x509.Certificate
	Peers           []string
	Logger          *zap.Logger
	TssEngine       tss.MessageReceiver
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
	)

	s := &server{
		UnimplementedDirectLinkServer: tsscommv1.UnimplementedDirectLinkServer{},
		ctx:                           nil, // to be set in Run(ctx context.Context).
		params:                        params,

		connections: map[string]outConnection{},

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
