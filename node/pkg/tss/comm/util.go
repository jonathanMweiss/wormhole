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

const maxBackoffTime = time.Minute
const minBackoffTime = time.Millisecond * 100

type dialWithBackoff struct {
	hostname       string
	attempt        uint64
	nextRedialTime time.Time
}

// Not thread safe
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
		d.attemptsPerPeer[hostname] = v + 1
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

	elem := heap.Pop(d).(dialWithBackoff)
	d.alreadyInHeap[elem.hostname] = false

	d.setTopAsTimer()
	return elem.hostname
}

func (d *backoffHeap) ResetAttempts(hostname string) {
	d.attemptsPerPeer[hostname] = 0
}

func (d *backoffHeap) setTopAsTimer() {
	if len(d.heap) == 0 {
		d.stopAndDrainTimer() // no elements: stop the timer.
		return
	}

	endTime := d.Peek().nextRedialTime

	d.stopAndDrainTimer()
	d.timer.Reset(time.Until(endTime))
}

func (d *backoffHeap) stopAndDrainTimer() {
	// stopping the timer, if its channel is not drained: drain it.
	if !d.timer.Stop() && len(d.timer.C) > 0 {
		<-d.timer.C
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

func (d *backoffHeap) Len() int { return len(d.heap) }
func (d *backoffHeap) Swap(i int, j int) {
	d.heap[i], d.heap[j] = d.heap[j], d.heap[i]
}
func (d *backoffHeap) Push(x any) {
	d.heap = append(d.heap, x.(dialWithBackoff))
}
func (d *backoffHeap) Peek() dialWithBackoff { return d.heap[0] }
func (d *backoffHeap) Less(i int, j int) bool {
	return d.heap[i].nextRedialTime.Before(d.heap[j].nextRedialTime)
}
func (d *backoffHeap) Pop() any {
	elem := d.heap[len(d.heap)-1]
	d.heap = d.heap[:len(d.heap)-1]
	return elem
}
