package comm

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
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
)

const workingServerSock = "127.0.0.1:5933"

type mockTssMessageHandler struct {
	chn              chan *tsscommv1.PropagatedMessage
	selfCert         *tls.Certificate
	peersToConnectTo []*x509.Certificate
	peerId           *tsscommv1.PartyId
}

func (m *mockTssMessageHandler) GetCertificate() *tls.Certificate { return m.selfCert }
func (m *mockTssMessageHandler) GetPeers() []*x509.Certificate    { return m.peersToConnectTo }
func (m *mockTssMessageHandler) FetchPartyId(*x509.Certificate) (*tsscommv1.PartyId, error) {
	return m.peerId, nil
}
func (m *mockTssMessageHandler) ProducedOutputMessages() <-chan *tsscommv1.PropagatedMessage {
	return m.chn
}
func (m *mockTssMessageHandler) HandleIncomingTssMessage(msg *tsscommv1.PropagatedMessage) {}

// wraps regular server and changes its Send function.
type testServer struct {
	*server
	atomic.Uint32
	done chan struct{}
}

func (w *testServer) Send(in tsscommv1.DirectLink_SendServer) error {
	fmt.Println("Send Called")
	prevVal := w.Uint32.Add(1)
	if prevVal == 2 {
		close(w.done)
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
		server: tmpSrvr.(*server),
		Uint32: atomic.Uint32{},
		done:   make(chan struct{}),
	}
	tstServer.server.ctx = ctx

	listener, err := net.Listen("tcp", workingServerSock)
	a.NoError(err)
	defer listener.Close()

	gserver := grpc.NewServer(tstServer.makeServerCredentials())
	defer gserver.Stop()

	tsscommv1.RegisterDirectLinkServer(gserver, &tstServer)
	go func() {
		err := gserver.Serve(listener)
		if err != nil {
			fmt.Println("WTF:", err)
		}
	}()

	PEMCert := en[0].GuardianStorage.TlsX509
	serverCert, err := internal.PemToCert(PEMCert)
	a.NoError(err)

	msgChan := make(chan *tsscommv1.PropagatedMessage)
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
	msgChan <- &tsscommv1.PropagatedMessage{
		Payload: &tsscommv1.PropagatedMessage_Echo{},
	}
	time.Sleep(time.Second * 2)

	msgChan <- &tsscommv1.PropagatedMessage{
		Payload: &tsscommv1.PropagatedMessage_Unicast{
			Unicast: &tsscommv1.SignedMessage{Recipients: []*tsscommv1.PartyId{
				{
					Id: workingServerSock,
				},
			}},
		},
	}

	select {
	case <-ctx.Done():
		t.FailNow()
	case <-tstServer.done:
	}
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
