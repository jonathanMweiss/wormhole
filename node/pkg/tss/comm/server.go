package comm

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"io"
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

type connection struct {
	cc     *grpc.ClientConn
	stream tsscommv1.DirectLink_SendClient
}

type redialResponse struct {
	name string
	conn *connection
}

// used by tests: ensures we can change the Send(inStream) functionality of the server.
type incomingStreamHandler interface {
	handleIncomingStream(inStream tsscommv1.DirectLink_SendServer) error
}

type server struct {
	tsscommv1.UnimplementedDirectLinkServer
	ctx context.Context

	incomingStreamHandler incomingStreamHandler
	params                *Parameters

	// to ensure thread-safety without locks, only the sender is allowed to change this map.
	connections map[string]*connection

	requestRedial chan string
	redials       chan redialResponse
}

func (s *server) run() {
	go s.dailer()

	for _, pid := range s.params.Peers {
		s.enqueueRedialRequest(pid.Id)
	}

	go s.sender()
}

func (s *server) sender() {
	connectionCheckTicker := time.NewTicker(time.Second * 5)
	for {
		select {
		case <-s.ctx.Done():
			// TODO: ensure streams and conns are closed.
			return

		case o := <-s.params.TssEngine.ProducedOutputMessages():
			//TODO: Ensure malicious server can't block a broadcast.
			s.send(o)
		case redial := <-s.redials:
			s.connections[redial.name] = redial.conn

		case <-connectionCheckTicker.C:
			// this case is an ensurance.
			s.ensuredConnected()
		}
	}
}

func (s *server) ensuredConnected() {
	if len(s.connections) != len(s.params.Peers) {
		for _, pid := range s.params.Peers {
			hostname := pid.Id
			if _, ok := s.connections[hostname]; !ok {
				s.enqueueRedialRequest(hostname)
			}
		}
	}
}

func (s *server) send(msg *tsscommv1.PropagatedMessage) {
	switch msg.Payload.(type) {
	case *tsscommv1.PropagatedMessage_Echo:
		s.broadcast(msg)

	case *tsscommv1.PropagatedMessage_Unicast:
		s.unicast(msg)
	}
}

func (s *server) unicast(msg *tsscommv1.PropagatedMessage) {
	m, ok := msg.Payload.(*tsscommv1.PropagatedMessage_Unicast)
	if !ok {
		panic("unicast should always be called with payload of type PropagatedMessage_Unicast")
	}

	for _, recipient := range m.Unicast.Recipients {
		hostname := recipient.Id
		conn, ok := s.connections[recipient.Id]
		if !ok {
			delete(s.connections, hostname)
			s.enqueueRedialRequest(hostname)

			s.params.Logger.Error(
				"received unknown recipient",
				zap.String("hostname", recipient.Id),
			)
			continue
		}

		if err := conn.stream.Send(msg); err != nil {
			delete(s.connections, hostname)
			s.enqueueRedialRequest(hostname)

			s.params.Logger.Warn(
				"couldn't send message to peer.",
				zap.String("hostname", recipient.Id),
				zap.Error(err),
			)
		}
	}
}

func (s *server) broadcast(msg *tsscommv1.PropagatedMessage) {
	for id, conn := range s.connections {
		if err := conn.stream.Send(msg); err != nil {
			delete(s.connections, id)
			s.enqueueRedialRequest(id)

			s.params.Logger.Warn(
				"couldn't send broadcast message to peer.",
				zap.String("hostname", id),
				zap.Error(err),
			)
		}
	}
}

func (s *server) enqueueRedialRequest(hostname string) {
	select {
	case <-s.ctx.Done():
		return
	case s.requestRedial <- hostname:
		s.params.Logger.Debug("requested redial", zap.String("hostname", hostname))
		return
	default:
		s.params.Logger.Warn("redial attempt failed", zap.String("hostname", hostname))
	}
}

func (s *server) dailer() {
	for {
		select {
		case <-s.ctx.Done():
			return

		case hostname := <-s.requestRedial:
			// TODO: add credentials
			cc, err := grpc.Dial(hostname, grpc.WithTransportCredentials(insecure.NewCredentials()))
			if err != nil {
				s.params.Logger.Error(
					"direct connection to peer failed",
					zap.Error(err),
					zap.String("hostname", hostname),
				)

				s.enqueueRedialRequest(hostname)
				time.Sleep(time.Millisecond * 10)

				continue
			}

			stream, err := tsscommv1.NewDirectLinkClient(cc).Send(s.ctx)
			if err != nil {
				cc.Close()

				s.params.Logger.Error(
					"setting direct stream to peer failed",
					zap.Error(err),
					zap.String("hostname", hostname),
				)

				s.enqueueRedialRequest(hostname)
				time.Sleep(time.Millisecond * 10)

				continue
			}

			s.redials <- redialResponse{
				name: hostname,
				conn: &connection{
					cc:     cc,
					stream: stream,
				},
			}
		}
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
	if s.incomingStreamHandler != nil {
		return s.incomingStreamHandler.handleIncomingStream(inStream)
	}

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
