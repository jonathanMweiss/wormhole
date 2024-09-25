package comm

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"strings"
	"time"

	tsscommv1 "github.com/certusone/wormhole/node/pkg/proto/tsscomm/v1"
	"github.com/certusone/wormhole/node/pkg/tss"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type connection struct {
	cc     *grpc.ClientConn
	stream tsscommv1.DirectLink_SendClient
}

type redialResponse struct {
	name string
	conn *connection
}

type server struct {
	tsscommv1.UnimplementedDirectLinkServer
	ctx        context.Context
	logger     *zap.Logger
	socketPath string

	tssMessenger tss.ReliableMessenger

	peers      []*tsscommv1.PartyId
	peerToCert map[string]*x509.Certificate
	// to ensure thread-safety without locks, only the sender is allowed to change this map.
	connections   map[string]*connection
	requestRedial chan string
	redials       chan redialResponse
}

func (s *server) run() {
	go s.dailer()
	go s.sender()

	for _, pid := range s.peers {
		s.enqueueRedialRequest(pid.Id)
	}
}

func (s *server) sender() {
	connectionCheckTicker := time.NewTicker(connectionCheckTime)

	for {
		select {
		case <-s.ctx.Done():
			for _, con := range s.connections {
				con.cc.Close()
			}

			return

		case o := <-s.tssMessenger.ProducedOutputMessages():
			s.send(o)

		case redial := <-s.redials:
			if _, ok := s.connections[redial.name]; ok {
				redial.conn.cc.Close() // shouldn't open the same connection twice.

				continue
			}

			s.connections[redial.name] = redial.conn

		case <-connectionCheckTicker.C:
			// this case is an ensurance.
			s.ensuredConnected()
		}
	}
}

func (s *server) ensuredConnected() {
	if len(s.connections) != len(s.peers) {
		for _, pid := range s.peers {
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
		return // shouldn't happen.
	}

	for _, recipient := range m.Unicast.Recipients {
		hostname := recipient.Id

		conn, ok := s.connections[recipient.Id]
		if !ok {
			s.enqueueRedialRequest(hostname)

			s.logger.Error(
				"received unknown recipient",
				zap.String("hostname", recipient.Id),
			)

			continue
		}

		if err := conn.stream.Send(msg); err != nil {
			delete(s.connections, hostname)
			s.enqueueRedialRequest(hostname)

			s.logger.Warn(
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

			s.logger.Warn(
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
		s.logger.Debug("requested redial", zap.String("hostname", hostname))

		return
	default:
		s.logger.Warn("couldn't send request to redial", zap.String("hostname", hostname))
	}
}

func (s *server) dailer() {
	// using a heap instead of time.AfterFunc/ After to reduce the number of
	// goroutines generated to 0 (not including the dialer itself).
	waiters := newBackoffHeap()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-waiters.timer.C:
			dialTo := waiters.Dequeue()
			if dialTo == "" {
				continue
			}

			if err := s.dial(dialTo); err != nil {
				s.logger.Error(
					"couldn't create direct link to peer",
					zap.Error(err),
					zap.String("hostname", dialTo),
				)

				waiters.Enqueue(dialTo)

				continue
			}

			s.logger.Info("dialed to peer", zap.String("hostname", dialTo))
			waiters.ResetAttempts(dialTo)

		case dialTo := <-s.requestRedial:
			waiters.Enqueue(dialTo)
		}
	}
}

func (s *server) dial(hostname string) error {
	pool := x509.NewCertPool()
	pool.AddCert(s.peerToCert[hostname]) // dialing to peer and accepting his cert only.

	cc, err := grpc.Dial(hostname,
		grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
			MinVersion:   tls.VersionTLS13,                                    // tls 1.3
			Certificates: []tls.Certificate{*s.tssMessenger.GetCertificate()}, // our cert to be sent to the peer.
			RootCAs:      pool,
		})),
	)
	if err != nil {
		return err
	}

	stream, err := tsscommv1.NewDirectLinkClient(cc).Send(s.ctx)
	if err != nil {
		cc.Close()

		return err
	}

	s.redials <- redialResponse{
		name: hostname,
		conn: &connection{
			cc:     cc,
			stream: stream,
		},
	}

	return nil
}

func (s *server) Send(inStream tsscommv1.DirectLink_SendServer) error {
	cert, err := extractClientCert(inStream.Context())
	if err != nil {
		s.logger.Error(
			"failed to receive incoming stream",
			zap.Error(err),
		)

		return err
	}

	clientId, err := s.tssMessenger.FetchPartyId(cert)
	if err != nil {
		return fmt.Errorf("unrecognized client: %w", err)
	}

	for {
		m, err := inStream.Recv()
		if err != nil {
			if err == io.EOF {
				s.logger.Info(
					"closing input stream",
					zap.String("peer", clientId.Id),
				)

				return nil
			}

			s.logger.Error(
				"error receiving from guardian. Closing connection",
				zap.Error(err),
				zap.String("peer", clientId.Id),
			)

			return err
		}

		// (SECURITY measure): ensuring received message has the ID of the correct sender.
		overwriteSenderID(m, clientId)
		s.tssMessenger.HandleIncomingTssMessage(m)
	}
}

func overwriteSenderID(m *tsscommv1.PropagatedMessage, clientId *tsscommv1.PartyId) {
	switch v := m.Payload.(type) {
	case *tsscommv1.PropagatedMessage_Echo:
		overwritePartyId(v.Echo.Echoer, clientId)
	case *tsscommv1.PropagatedMessage_Unicast:
		overwritePartyId(v.Unicast.Sender, clientId)
	}
}

func overwritePartyId(curr *tsscommv1.PartyId, overwritingId *tsscommv1.PartyId) {
	curr.Id = strings.Clone(overwritingId.Id)
	curr.Key = make([]byte, len(overwritingId.Key))
	copy(curr.Key, overwritingId.Key)
}
