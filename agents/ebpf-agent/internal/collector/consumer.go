package collector

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"

	"ebpf-agent/internal/events"

	"github.com/cilium/ebpf/ringbuf"
)

// ConsumeEvents reads FlowEvents from the ringbuf until ctx is cancelled.
// Each decoded event is sent on the returned channel. The channel is closed
// when the consumer exits.
func ConsumeEvents(ctx context.Context, rd *ringbuf.Reader) <-chan events.FlowEvent {
	ch := make(chan events.FlowEvent, 256)

	go func() {
		defer close(ch)
		for {
			rec, err := rd.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					return
				}
				log.Printf("ringbuf read: %v", err)
				continue
			}

			ev, err := DecodeFlowEvent(rec.RawSample)
			if err != nil {
				log.Printf("decode event: %v", err)
				continue
			}

			select {
			case ch <- ev:
			case <-ctx.Done():
				return
			}
		}
	}()

	return ch
}

func DecodeFlowEvent(raw []byte) (events.FlowEvent, error) {
	var ev events.FlowEvent
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &ev); err != nil {
		return ev, fmt.Errorf("binary decode: %w", err)
	}
	return ev, nil
}

// FormatIP returns the human-readable form of the IP stored in a FlowEvent.
func FormatIP(ip [16]byte, version uint8) string {
	if version == 4 {
		return net.IP(ip[:4]).String()
	}
	return net.IP(ip[:]).String()
}
