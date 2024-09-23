package comm

import (
	"container/heap"
	"context"
	"crypto/x509"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

const (
	maxAttempts    = 10 // max backoff attempts before time doesn't increase.
	minBackoffTime = time.Millisecond * 100
	maxBackoffTime = minBackoffTime * 1024

	connectionCheckTime = time.Second * 5
)

type dialWithBackoff struct {
	hostname       string
	attempt        uint64
	nextRedialTime time.Time
}

// NOT THREAD SAFE! do NOT share between two different goroutines.
type backoffHeap struct {
	heap            []dialWithBackoff
	timer           *time.Timer
	alreadyInHeap   map[string]bool
	attemptsPerPeer map[string]uint64 // on successful dial, reset to 0.
}

// Enqueue adds a hostname to the heap, with a new backoff time.
func (d *backoffHeap) Enqueue(hostname string) {
	if d.alreadyInHeap[hostname] {
		return
	}

	if v, ok := d.attemptsPerPeer[hostname]; ok {
		newv := v + 1
		if newv >= maxAttempts {
			newv = maxAttempts
		}

		d.attemptsPerPeer[hostname] = newv
	} else {
		d.attemptsPerPeer[hostname] = 0
	}

	elem := dialWithBackoff{
		hostname: hostname,
		attempt:  d.attemptsPerPeer[hostname],
	}

	elem.setBackoff()
	heap.Push(d, elem)
	d.alreadyInHeap[hostname] = true

	d.setTopAsTimer()
}

func (d *backoffHeap) Dequeue() string {
	if len(d.heap) == 0 {
		return ""
	}

	elem, ok := heap.Pop(d).(dialWithBackoff)
	if !ok {
		return "" // shouldn't happen.
	}

	d.alreadyInHeap[elem.hostname] = false

	d.setTopAsTimer()

	return elem.hostname
}

func (d *backoffHeap) ResetAttempts(hostname string) {
	delete(d.attemptsPerPeer, hostname)
}

func (d *backoffHeap) setTopAsTimer() {
	if len(d.heap) == 0 {
		d.stopAndDrainTimer() // no elements: stop the timer.

		return
	}

	endTime := d.peek().nextRedialTime // we have at least one element.

	d.stopAndDrainTimer()
	d.timer.Reset(time.Until(endTime))
}

func (d *backoffHeap) stopAndDrainTimer() {
	// stopping the timer, if its channel is not drained: drain it.
	if !d.timer.Stop() && len(d.timer.C) > 0 {
		select {
		case <-d.timer.C:
		default:
		}
	}
}

func newBackoffHeap() backoffHeap {
	b := backoffHeap{
		heap:            []dialWithBackoff{},
		timer:           time.NewTimer(time.Second),
		alreadyInHeap:   map[string]bool{},
		attemptsPerPeer: map[string]uint64{},
	}
	heap.Init(&b)

	b.stopAndDrainTimer() // ensuring it doesn't fire when empty.

	return b
}

func (d *dialWithBackoff) setBackoff() {
	duration := minBackoffTime * (1 << uint(d.attempt))
	if duration < minBackoffTime {
		duration = minBackoffTime // ensuring overflow doesn't write minus duration.
	} else if duration > maxBackoffTime {
		duration = maxBackoffTime
	}

	d.nextRedialTime = time.Now().Add(duration)
}

func extractClientCert(ctx context.Context) (*x509.Certificate, error) {
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

	return clientCert, nil
}

// Interface for heap, don't use directly.

func (d *backoffHeap) Len() int {
	return len(d.heap)
}

func (d *backoffHeap) Swap(i int, j int) {
	d.heap[i], d.heap[j] = d.heap[j], d.heap[i]
}

func (d *backoffHeap) Push(x any) {
	if v, ok := x.(dialWithBackoff); ok {
		d.heap = append(d.heap, v)
	}
}

func (d *backoffHeap) peek() *dialWithBackoff {
	if len(d.heap) == 0 {
		return nil
	}

	return &d.heap[0]
}

func (d *backoffHeap) Less(i int, j int) bool {
	return d.heap[i].nextRedialTime.Before(d.heap[j].nextRedialTime)
}

func (d *backoffHeap) Pop() any {
	elem := d.heap[len(d.heap)-1]
	d.heap = d.heap[:len(d.heap)-1]

	return elem
}
