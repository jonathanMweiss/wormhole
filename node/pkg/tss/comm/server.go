package comm

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"io"
	"net"
	"sync/atomic"
	"time"

	tsscommv1 "github.com/certusone/wormhole/node/pkg/proto/tsscomm/v1"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

const (
	disconnected uint32 = 0
	connected    uint32 = 1
)

type connection struct {
	cc     *grpc.ClientConn
	stream tsscommv1.DirectLink_SendClient

	state atomic.Uint32
}

type server struct {
	tsscommv1.UnimplementedDirectLinkServer
	ctx context.Context

	params      *Parameters
	connections map[string]*connection

	gserver  *grpc.Server
	listener net.Listener
}

func (s *server) establishConnections(errChn chan error) {
	// TODO: to avoid the following, we need to set each connection with its own goroutine.
	// for c:= range connection {
	// 		c.send() // blocking
	// }

	// TODO: make the dailer goroutine able to attempt reconnection with some node that fails.
	// for instance was connected, then for some reason a connection fails, then the dailer will eventually attempt to redial.
	go s.dialer()
	// go s.sender()
}

// goroutine ensuring connections are evenetually set.
func (s *server) dialer() {
	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		failedToConnect := false
		for _, hostname := range s.params.Peers {
			con := s.connections[hostname.Id]
			if disconnected != con.state.Load() {
				continue
			}

			// TODO: add credentials
			cc, err := grpc.Dial(hostname.Id, grpc.WithTransportCredentials(insecure.NewCredentials()))
			if err != nil {
				s.params.Logger.Error(
					"direct connection to peer failed",
					zap.Error(err),
					zap.String("hostname", hostname.Id),
				)
				failedToConnect = true
				continue
			}

			stream, err := tsscommv1.NewDirectLinkClient(cc).Send(s.ctx)
			if err != nil {
				cc.Close()
				s.params.Logger.Error(
					"setting direct stream to peer failed",
					zap.Error(err),
					zap.String("hostname", hostname.Id),
				)
				failedToConnect = true
				continue
			}

			con.cc = cc
			con.stream = stream
			con.state.Store(connected)
		}

		if !failedToConnect {
			return
		}

		time.Sleep(time.Second * 5)
	}
}

func extractClientCert(ctx context.Context) (*ecdsa.PublicKey, error) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return nil, status.Error(codes.InvalidArgument, "unable to retrieve peer from context")
	}

	// Extract AuthInfo (TLS information)
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return nil, status.Error(codes.InvalidArgument, "unexpected peer transport credentials type, please use tls")
	}

	// Get the client certificate
	if len(tlsInfo.State.PeerCertificates) == 0 {
		return nil, status.Error(codes.InvalidArgument, "no client certificate provided")
	}

	clientCert := tlsInfo.State.PeerCertificates[0]
	if clientCert.PublicKeyAlgorithm != x509.ECDSA {
		return nil, status.Error(codes.InvalidArgument, "certificate must use ECDSA")
	}

	// get public key from client certificate.
	pk, ok := clientCert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, status.Error(codes.InvalidArgument, "certificate doesn't hold ecdas public key")
	}

	return pk, nil
}

func (s *server) Send(inStream tsscommv1.DirectLink_SendServer) error {
	pk, err := extractClientCert(inStream.Context())
	if err != nil {
		s.params.Logger.Error(
			"failed to receive incoming stream",
			zap.Error(err),
		)

		return err
	}

	clientId := s.params.TssEngine.FetchPartyId(pk)

	// TODO: Ensure that only a single Send() is called at most once by each peer.
	for {
		// TODO: ensure we don't need to check the ctx of the server.
		//       (im pretty sure the grpcserver closes all incoming streams)
		m, err := inStream.Recv()
		if err != nil {
			if err == io.EOF {
				s.params.Logger.Info("closing input stream")
				// TODO: State the client disconnected.
				return nil
			}

			// TODO add identifier of the guardian.
			s.params.Logger.Error("error receiving from guardian. Closing connection", zap.Error(err))
			return err
		}

		// ensuring received message has the ID of the correct sender.
		switch v := m.Payload.(type) {
		case *tsscommv1.PropagatedMessage_Echo:
			v.Echo.Echoer = clientId
		case *tsscommv1.PropagatedMessage_Unicast:
			v.Unicast.Sender = clientId
		}

		s.params.TssEngine.HandleIncomingTssMessage(m)
	}
}
