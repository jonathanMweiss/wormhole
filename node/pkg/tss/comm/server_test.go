package comm

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
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
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

type mockTssMessageHandler struct {
	chn chan *tsscommv1.PropagatedMessage
}

// FetchPartyId implements tss.ReliableMessageHandler.
func (m *mockTssMessageHandler) FetchPartyId(*ecdsa.PublicKey) *tsscommv1.PartyId {
	return &tsscommv1.PartyId{Id: "mock", Moniker: "mock", Key: []byte("mock"), Index: 0}
}
func (m *mockTssMessageHandler) HandleIncomingTssMessage(msg *tsscommv1.PropagatedMessage) {}
func (m *mockTssMessageHandler) ProducedOutputMessages() <-chan *tsscommv1.PropagatedMessage {
	return m.chn
}

// wraps regular server and changes its Send function.
type testServer struct {
	*server
	atomic.Uint32
	done chan struct{}
}

func (w *testServer) Send(in tsscommv1.DirectLink_SendServer) error {
	prevVal := w.Uint32.Add(1)
	if prevVal == 2 {
		close(w.done)
	}
	return io.EOF
}

func TestRedial(t *testing.T) {
	a := require.New(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	ctx = testutils.MakeSupervisorContext(ctx)

	workingServerSock := "127.0.0.1:5933"
	dialName := workingServerSock

	tmpSrvr := NewServer(&Parameters{
		SocketPath:      workingServerSock,
		SelfCredentials: tls.Certificate{},
		Logger:          supervisor.Logger(ctx),
		TssEngine:       &mockTssMessageHandler{nil}, // doesn't generate messages
		Peers:           []*tsscommv1.PartyId{},      // no peers
	})
	tstServer := testServer{
		server: tmpSrvr.(*server),
		Uint32: atomic.Uint32{},
		done:   make(chan struct{}),
	}
	tstServer.server.ctx = ctx

	listener, err := net.Listen("tcp", workingServerSock)
	a.NoError(err)
	defer listener.Close()

	gserver := grpc.NewServer()
	defer gserver.Stop()

	tsscommv1.RegisterDirectLinkServer(gserver, &tstServer)
	go func() {
		err := gserver.Serve(listener)
		if err != nil {
			fmt.Println("WTF:", err)
		}
	}()

	msgCreator := &mockTssMessageHandler{make(chan *tsscommv1.PropagatedMessage, 1)}
	srvr := NewServer(&Parameters{
		SocketPath:      "localhost:5930",
		SelfCredentials: tls.Certificate{},
		Logger:          supervisor.Logger(ctx),
		TssEngine:       msgCreator,
		Peers: []*tsscommv1.PartyId{
			{
				Id: dialName, // connect to testServer.
			},
		},
	})

	srv := srvr.(*server)
	srv.ctx = ctx
	// setting up server dailer and sender
	srv.run()
	time.Sleep(time.Second)

	//should cause disconnect
	msgCreator.chn <- &tsscommv1.PropagatedMessage{
		Payload: &tsscommv1.PropagatedMessage_Echo{},
	}
	time.Sleep(time.Second * 2)

	msgCreator.chn <- &tsscommv1.PropagatedMessage{
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

func TestE2E(t *testing.T) {
	a := require.New(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	ctx = testutils.MakeSupervisorContext(ctx)

	engines, err := _loadGuardians(5)
	a.NoError(err)

	// create servers.
	servers := make([]*server, 5)
	for i := 0; i < 5; i++ {
		servers[i] = NewServer(&Parameters{
			SocketPath: fmt.Sprintf("localhost:%d", 5930+i),
			Logger:     supervisor.Logger(ctx),
			TssEngine:  engines[i],
		}).(*server)
		servers[i].ctx = ctx
	}

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
