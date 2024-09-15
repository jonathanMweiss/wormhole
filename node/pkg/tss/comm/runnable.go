package comm

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"

	"github.com/certusone/wormhole/node/pkg/tss"
	"go.uber.org/zap"
)

type Parameters struct {
	SocketPath      string
	SelfCredentials tls.Certificate
	CA              x509.Certificate
	Peers           []string
	Logger          *zap.Logger
	TssEngine       tss.ReliableMessageHandler
}

type server struct {
}

func NewServer(params *Parameters) *server {
	return nil
}

func (s *server) Run(ctx context.Context) error {
	if s == nil {
		return fmt.Errorf("tsscomm.server is nil")
	}
	// 	//TODO. Set up the server here.
	// 	// set up a goroutine that listens on its error etc.
	// 	// set up its connections (ensure it awaits for a few moments after the server is up and running.)

	// func(ctx context.Context) error {
	// 	go func() {
	// 		errC <- srv.Serve(l)
	// 	}()

	// 	go srvice.makeConnections(ctx, errC) // if they all get up at the same time, then it'll need to wait a few moments to set up all streams.
	// 	select {
	// 	case <-ctx.Done():
	// 		srv.Stop()
	// 		return ctx.Err()
	// 	case err := <-errC:
	// 		grpcServer.Stop()
	// 		return err
	// 		return nil
	// 	}
	// }
	return nil
}
