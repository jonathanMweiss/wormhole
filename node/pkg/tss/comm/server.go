package comm

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"io"
	"net"

	tsscommv1 "github.com/certusone/wormhole/node/pkg/proto/tsscomm/v1"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

type outConnection struct {
	stream            tsscommv1.DirectLink_SendClient
	sendToNetworkChan chan tsscommv1.PropagatedMessage
}

type server struct {
	tsscommv1.UnimplementedDirectLinkServer
	ctx context.Context

	params      *Parameters
	connections map[string]outConnection

	gserver  *grpc.Server
	listener net.Listener
}

func (s *server) establishConnections(errChn chan error) {
	// TODO: to avoid the following, we need to set each connection with its own goroutine.
	// for c:= range connection {
	// 		c.send() // blocking
	// }

	for range s.params.Peers {
		// TODO
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
