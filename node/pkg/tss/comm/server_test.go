package comm

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/certusone/wormhole/node/pkg/internal/testutils"
	tsscommv1 "github.com/certusone/wormhole/node/pkg/proto/tsscomm/v1"
	"github.com/certusone/wormhole/node/pkg/supervisor"
	"github.com/certusone/wormhole/node/pkg/tss"
	"github.com/certusone/wormhole/node/pkg/tss/internal"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

const workingServerSock = "127.0.0.1:5933"

var workingServerAsMessageRecipient = []*tsscommv1.PartyId{&tsscommv1.PartyId{
	Id: workingServerSock,
}}

type mockTssMessageHandler struct {
	chn              chan tss.Sendable
	selfCert         *tls.Certificate
	peersToConnectTo []*x509.Certificate
	peerId           *tsscommv1.PartyId
}

func (m *mockTssMessageHandler) GetCertificate() *tls.Certificate { return m.selfCert }
func (m *mockTssMessageHandler) GetPeers() []*x509.Certificate    { return m.peersToConnectTo }
func (m *mockTssMessageHandler) FetchPartyId(*x509.Certificate) (*tsscommv1.PartyId, error) {
	return m.peerId, nil
}
func (m *mockTssMessageHandler) ProducedOutputMessages() <-chan tss.Sendable {
	return m.chn
}
func (m *mockTssMessageHandler) HandleIncomingTssMessage(msg tss.Incoming) {}

// wraps regular server and changes its Send function.
type testServer struct {
	*server
	atomic.Uint32
	done                         chan struct{}
	numberOfReconnectionAttempts int
	// when set to true, the server will block for 30 seconds.
	isMaliciousBlocker bool
}

func (w *testServer) Send(in tsscommv1.DirectLink_SendServer) error {
	prevVal := w.Uint32.Add(1)
	if int(prevVal) == w.numberOfReconnectionAttempts {
		close(w.done)
	}
	if w.isMaliciousBlocker {
		time.Sleep(time.Second * 30)
	}

	return io.EOF
}

func TestTLSConnectAndRedial(t *testing.T) {
	a := require.New(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	ctx = testutils.MakeSupervisorContext(ctx)

	en, err := _loadGuardians(2)
	a.NoError(err)

	tmpSrvr, err := NewServer(workingServerSock, supervisor.Logger(ctx), &mockTssMessageHandler{
		chn:      nil,
		selfCert: en[0].GetCertificate(),
		// connect to no one.
		peersToConnectTo: en[0].GetPeers(), // Give the peer a certificate.
		peerId:           &tsscommv1.PartyId{},
	})
	a.NoError(err)

	tstServer := testServer{
		server:                       tmpSrvr.(*server),
		Uint32:                       atomic.Uint32{},
		done:                         make(chan struct{}),
		numberOfReconnectionAttempts: 2,
	}
	tstServer.server.ctx = ctx

	listener, err := net.Listen("tcp", workingServerSock)
	a.NoError(err)
	defer listener.Close()

	gserver := grpc.NewServer(tstServer.makeServerCredentials())
	defer gserver.Stop()

	tsscommv1.RegisterDirectLinkServer(gserver, &tstServer)
	go gserver.Serve(listener)

	PEMCert := en[0].GuardianStorage.TlsX509
	serverCert, err := internal.PemToCert(PEMCert)
	a.NoError(err)

	msgChan := make(chan tss.Sendable)
	srvr, err := NewServer("localhost:5930", supervisor.Logger(ctx), &mockTssMessageHandler{
		chn:              msgChan,
		selfCert:         en[1].GetCertificate(),
		peersToConnectTo: []*x509.Certificate{serverCert}, // will ask to fetch each peer (and return the below peerId)
		peerId: &tsscommv1.PartyId{
			Id: workingServerSock,
		},
	})
	a.NoError(err)

	srv := srvr.(*server)
	srv.ctx = ctx
	// setting up server dailer and sender
	srv.run()
	time.Sleep(time.Second)

	//should cause disconnect
	msgChan <- &tss.Echo{
		Echo:       &tsscommv1.Echo{},
		Recipients: workingServerAsMessageRecipient,
	}
	time.Sleep(time.Second * 2)

	msgChan <- &tss.Unicast{
		Receipients: workingServerAsMessageRecipient,
	}

	select {
	case <-ctx.Done():
		t.FailNow()
	case <-tstServer.done:
	}
}

func TestRelentlessReconnections(t *testing.T) {
	a := require.New(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*15)
	defer cancel()
	ctx = testutils.MakeSupervisorContext(ctx)

	en, err := _loadGuardians(2)
	a.NoError(err)

	PEMCert := en[0].GuardianStorage.TlsX509
	serverCert, err := internal.PemToCert(PEMCert)
	a.NoError(err)

	msgChan := make(chan tss.Sendable)
	srvr, err := NewServer("localhost:5930", supervisor.Logger(ctx), &mockTssMessageHandler{
		chn:              msgChan,
		selfCert:         en[1].GetCertificate(),
		peersToConnectTo: []*x509.Certificate{serverCert}, // will ask to fetch each peer (and return the below peerId)
		peerId: &tsscommv1.PartyId{
			Id: workingServerSock,
		},
	})
	a.NoError(err)

	srv := srvr.(*server)
	srv.ctx = ctx
	// setting up server dailer and sender
	srv.run()

	tmpSrvr, err := NewServer(workingServerSock, supervisor.Logger(ctx), &mockTssMessageHandler{
		chn:      nil,
		selfCert: en[0].GetCertificate(),
		// connect to no one.
		peersToConnectTo: en[0].GetPeers(), // Give the peer a certificate.
		peerId:           &tsscommv1.PartyId{},
	})
	a.NoError(err)

	tstServer := testServer{
		server:                       tmpSrvr.(*server),
		Uint32:                       atomic.Uint32{},
		done:                         make(chan struct{}),
		numberOfReconnectionAttempts: 5,
	}
	tstServer.server.ctx = ctx

	listener, err := net.Listen("tcp", workingServerSock)
	a.NoError(err)
	defer listener.Close()

	gserver := grpc.NewServer(tstServer.makeServerCredentials())
	defer gserver.Stop()

	tsscommv1.RegisterDirectLinkServer(gserver, &tstServer)
	go gserver.Serve(listener)

	for i := 0; i < 10; i++ {
		msgChan <- &tss.Unicast{
			Unicast:     &tsscommv1.TssContent{},
			Receipients: workingServerAsMessageRecipient,
		}

		select {
		case <-ctx.Done():
			t.FailNow()
		case <-tstServer.done:
			return // only way to pass the test.
		default:
			time.Sleep(time.Millisecond * 100)
		}
	}

	t.FailNow()
}

type tssMockJustForMessageGeneration struct {
	tss.ReliableMessenger
	chn chan tss.Sendable
}

func (m *tssMockJustForMessageGeneration) ProducedOutputMessages() <-chan tss.Sendable {
	return m.chn
}
func TestNonBlockedBroadcast(t *testing.T) {
	a := require.New(t)

	workingServers := []string{"localhost:5500", "localhost:5501"}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*40)
	defer cancel()
	ctx = testutils.MakeSupervisorContext(ctx)

	en, err := _loadGuardians(3)
	a.NoError(err)

	donechns := make([]chan struct{}, 2)
	// set servers up.
	for i := 0; i < 2; i++ {
		tmpSrvr, err := NewServer(workingServers[i], supervisor.Logger(ctx), &mockTssMessageHandler{
			chn:              nil,
			selfCert:         en[i].GetCertificate(),
			peersToConnectTo: en[0].GetPeers(), // Give the peer a certificate.
			peerId:           &tsscommv1.PartyId{},
		})
		a.NoError(err)

		tstServer := testServer{
			server:                       tmpSrvr.(*server),
			Uint32:                       atomic.Uint32{},
			done:                         make(chan struct{}),
			numberOfReconnectionAttempts: 1,
			isMaliciousBlocker:           true,
		}
		donechns[i] = tstServer.done
		tstServer.server.ctx = ctx

		listener, err := net.Listen("tcp", workingServers[i])
		a.NoError(err)
		defer listener.Close()

		gserver := grpc.NewServer(tstServer.makeServerCredentials())
		defer gserver.Stop()

		tsscommv1.RegisterDirectLinkServer(gserver, &tstServer)
		go gserver.Serve(listener)
	}

	for _, v := range en[2].Guardians {
		if v.Id == en[0].Self.Id {
			v.Id = "localhost:5500"
			continue
		}
		if v.Id == en[1].Self.Id {
			v.Id = "localhost:5501"
			continue
		}
		v.Id = ""

	}

	msgChan := make(chan tss.Sendable)
	srvr, err := NewServer("localhost:5930", supervisor.Logger(ctx), &tssMockJustForMessageGeneration{
		ReliableMessenger: en[2],
		chn:               msgChan,
	})
	a.NoError(err)

	srv := srvr.(*server)
	srv.ctx = ctx
	// setting up server dailer and sender
	srv.run()
	time.Sleep(time.Second)

	numDones := 0
	for i := 0; i < 10; i++ {
		msgChan <- &tss.Echo{
			Recipients: workingServerAsMessageRecipient,
		}

		select {
		case <-ctx.Done():
			t.FailNow()
		case <-donechns[0]:
			numDones += 1
		case <-donechns[1]:
			numDones += 1
		default:
			time.Sleep(time.Millisecond * 100)
		}
	}
	if numDones >= 2 {
		return
	}

	cancel()
	t.FailNow()

}

func TestBackoff(t *testing.T) {
	a := require.New(t)
	ctx, cncl := context.WithTimeout(context.Background(), time.Second*5)
	defer cncl()

	t.Run("basic1", func(t *testing.T) {
		heap := newBackoffHeap()

		heap.Enqueue("3")
		a.Equal("3", heap.Dequeue())
		heap.Enqueue("3")
		heap.Enqueue("1")
		heap.Enqueue("2")

		expected := []string{"1", "2", "3"}
		for i := 0; i < 3; i++ {
			select {
			case <-ctx.Done():
				t.FailNow()
			case <-heap.timer.C:
				hostname := heap.Dequeue()
				a.Equal(expected[i], hostname)
			}
		}
	})

	t.Run("basic2", func(t *testing.T) {
		heap := newBackoffHeap()

		heap.Enqueue("1")
		a.Equal("1", heap.Dequeue())
		heap.ResetAttempts("1")
		heap.Enqueue("1")
		heap.Enqueue("2")
		heap.Enqueue("3")

		expected := []string{"1", "2", "3"}
		for i := 0; i < 3; i++ {
			select {
			case <-ctx.Done():
				t.FailNow()
			case <-heap.timer.C:
				hostname := heap.Dequeue()
				a.Equal(expected[i], hostname)
			}
		}
	})

	t.Run("complex", func(t *testing.T) {
		heap := newBackoffHeap()

		// operations on an empty heap:
		heap.stopAndDrainTimer()
		heap.stopAndDrainTimer()
		heap.stopAndDrainTimer()
		heap.setTopAsTimer()
		a.Equal("", heap.Dequeue())

		heap.ResetAttempts("1")
		heap.Enqueue("1")
		heap.Enqueue("1")
		heap.Enqueue("1")
		heap.Enqueue("1")
		a.Equal("1", heap.Dequeue())

		heap.ResetAttempts("1")
		heap.Enqueue("1")
		heap.Enqueue("2")
		heap.Enqueue("3")
		heap.Enqueue("2")
		a.Equal("1", heap.Dequeue())
		a.Equal("2", heap.Dequeue())

		heap.ResetAttempts("2")
		heap.Enqueue("2")
		heap.Enqueue("4")
		heap.Enqueue("5")

		expected := []string{"3", "2", "4", "5"}
		for i := 0; i < 3; i++ {
			select {
			case <-ctx.Done():
				t.FailNow()
			case <-heap.timer.C:
				hostname := heap.Dequeue()
				a.Equal(expected[i], hostname)
			}
		}
	})

	t.Run("maxAndMinValue", func(t *testing.T) {
		maxBackoffTime := (&dialWithBackoff{attempt: maxBackoffTimeModifier})._durationBasedOnNumberOfAttempts()

		heap := newBackoffHeap()

		heap.attemptsPerPeer["1"] = 23144532345345665 // large number.
		heap.Enqueue("1")
		v := heap.peek()

		a.True(v.nextRedialTime.Before(time.Now().Add(maxBackoffTime)))
		a.True(v.nextRedialTime.After(time.Now().Add(maxBackoffTime - time.Second)))

		a.Equal("1", heap.Dequeue())
		timenow := time.Now()
		heap.ResetAttempts("1")
		heap.Enqueue("1")
		v = heap.peek()
		a.True(v.nextRedialTime.Before(timenow.Add(minBackoffTime + 10*time.Millisecond)))
		a.True(v.nextRedialTime.After(timenow.Add(minBackoffTime - 10*time.Millisecond)))

	})
}

// TODO: this is a copy-paste from tss/implementation_test.go
func loadMockGuardianStorage(gstorageIndex int) (*tss.GuardianStorage, error) {
	path, err := testutils.GetMockGuardianTssStorage(gstorageIndex)
	if err != nil {
		return nil, err
	}

	st, err := tss.NewGuardianStorageFromFile(path)
	if err != nil {
		return nil, err
	}
	return st, nil
}

// TODO: this is a copy-paste from tss/implementation_test.go
func _loadGuardians(numParticipants int) ([]*tss.Engine, error) {
	engines := make([]*tss.Engine, numParticipants)

	for i := 0; i < numParticipants; i++ {
		gs, err := loadMockGuardianStorage(i)
		if err != nil {
			return nil, err
		}

		e, err := tss.NewReliableTSS(gs)
		if err != nil {
			return nil, err
		}

		en, ok := e.(*tss.Engine)
		if !ok {
			return nil, errors.New("not an engine")
		}
		engines[i] = en
	}

	return engines, nil
}

type testCAInspectionFailForNonCACerts struct {
	*server
	atomic.Uint32
	done                         chan struct{}
	numberOfReconnectionAttempts int
	// when set to true, the server will block for 30 seconds.
	isMaliciousBlocker bool
}

func TestNotAcceptNonCAs(t *testing.T) {
	a := require.New(t)

	en, err := _loadGuardians(2)
	a.NoError(err)

	// ============
	// Creating new Cert which is NOT a CA
	// ============

	serverCert, err := internal.PemToCert(en[0].GuardianStorage.TlsX509)
	a.NoError(err)

	rootKey, err := internal.PemToPrivateKey(en[0].PrivateKey)
	a.NoError(err)
	clientTlsCert, clientCert := tlsCert(serverCert, rootKey)

	// ============
	// setting server up, with this Cert allowed
	// ============

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*60)
	defer cancel()
	ctx = testutils.MakeSupervisorContext(ctx)

	tmp, err := NewServer(workingServerSock, supervisor.Logger(ctx), &mockTssMessageHandler{
		chn:      nil,
		selfCert: en[0].GetCertificate(),
		// connect to no one.
		peersToConnectTo: []*x509.Certificate{clientCert}, // Give the peer a certificate.
		peerId:           &tsscommv1.PartyId{},
	})
	a.NoError(err)

	server := tmp.(*server)
	server.ctx = ctx

	listener, err := net.Listen("tcp", workingServerSock)
	a.NoError(err)
	defer listener.Close()

	gserver := grpc.NewServer(server.makeServerCredentials())
	defer gserver.Stop()

	tsscommv1.RegisterDirectLinkServer(gserver, server)
	go gserver.Serve(listener)

	time.Sleep(time.Millisecond * 200)
	// ============
	// trying to send message using cert
	// ============
	pool := x509.NewCertPool()

	runningServerX509, err := internal.PemToCert(en[0].GuardianStorage.TlsX509)
	a.NoError(err)

	pool.AddCert(runningServerX509) // dialing to peer and accepting his cert only.

	cc, err := grpc.Dial(workingServerSock,
		grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
			MinVersion:   tls.VersionTLS13,                  // tls 1.3
			Certificates: []tls.Certificate{*clientTlsCert}, // our cert to be sent to the peer.
			RootCAs:      pool,
		})),
	)
	a.NoError(err)

	defer cc.Close()

	stream, err := tsscommv1.NewDirectLinkClient(cc).Send(ctx)
	a.NoError(err)

	stream.Send(&tsscommv1.PropagatedMessage{})
	_, err = stream.CloseAndRecv()
	a.ErrorContains(err, "not a CA")
}

func tlsCert(rootCA *x509.Certificate, rootKey *ecdsa.PrivateKey) (*tls.Certificate, *x509.Certificate) {
	template := *rootCA
	// this cert will be the CA that we will use to sign the server cert
	template.IsCA = false
	// describe what the certificate will be used for
	template.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature
	template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	pubcert, certpem, err := internal.CreateCert(&template, rootCA, &priv.PublicKey, rootKey)
	if err != nil {
		panic(err)
	}

	tlscert, err := tls.X509KeyPair(certpem, internal.PrivateKeyToPem(priv))
	if err != nil {
		panic(err)
	}
	return &tlscert, pubcert
}
