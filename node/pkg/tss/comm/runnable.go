package comm

import (
	"context"
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

func NewServer(socketPath string, logger *zap.Logger, tssMessenger tss.ReliableMessenger) DirectLink {

	peers := tssMessenger.GetPeers()
	partyIds := make([]*tsscommv1.PartyId, len(peers))
	for i, peer := range peers {
		partyIds[i] = tssMessenger.FetchPartyId(peer)
	}

	return &server{
		UnimplementedDirectLinkServer: tsscommv1.UnimplementedDirectLinkServer{},
		ctx:                           nil, // set up in Run(ctx)
		logger:                        logger,
		socketPath:                    socketPath,

		tssMessenger: tssMessenger,

		peers:         partyIds,
		connections:   make(map[string]*connection, len(peers)),
		requestRedial: make(chan string, len(peers)),
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

	listener, err := net.Listen("tcp", s.socketPath)
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

	s.logger.Info("admin server listening on", zap.String("path", s.socketPath))

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
