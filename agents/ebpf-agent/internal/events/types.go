package events

// FlowKey mirrors struct flow_key in bpf/common.h.  44 bytes.
// Used as the key for BPF PERCPU_HASH map lookups.
type FlowKey struct {
	SrcIP     [16]byte // off=0   size=16
	DstIP     [16]byte // off=16  size=16
	SrcPort   uint16   // off=32  size=2
	DstPort   uint16   // off=34  size=2
	Protocol  uint8    // off=36  size=1
	IPVersion uint8    // off=37  size=1
	_         [2]byte  // off=38  size=2  (explicit padding, matches C _pad[2])
	IfIndex   uint32   // off=40  size=4
} // Total: 44 bytes

// FlowMetrics mirrors struct flow_metrics in bpf/common.h.  32 bytes.
// Per-CPU value in the flow aggregation map.
type FlowMetrics struct {
	Bytes     uint64 // off=0   size=8
	Packets   uint64 // off=8   size=8
	FirstSeen uint64 // off=16  size=8
	LastSeen  uint64 // off=24  size=8
} // Total: 32 bytes

// FlowEvent is the aggregated output emitted to the rest of the pipeline.
// Assembled from FlowKey + summed FlowMetrics during periodic map reads.
type FlowEvent struct {
	TSUnixNano uint64
	IfIndex    uint32
	IPVersion  uint8
	Protocol   uint8
	SrcIP      [16]byte
	DstIP      [16]byte
	SrcPort    uint16
	DstPort    uint16
	Bytes      uint64
	Packets    uint64
}
