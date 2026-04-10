package events

// FlowEvent mirrors struct flow_event in bpf/common.h.
// Field order and sizes must match exactly for binary decoding.
type FlowEvent struct {
	TSUnixNano uint64   // off=0   size=8
	IfIndex    uint32   // off=8   size=4
	IPVersion  uint8    // off=12  size=1  (inner IP version for VXLAN)
	Protocol   uint8    // off=13  size=1
	SrcIP      [16]byte // off=14  size=16 (inner src for VXLAN)
	DstIP      [16]byte // off=30  size=16 (inner dst for VXLAN)
	SrcPort    uint16   // off=46  size=2  (inner ports for VXLAN)
	DstPort    uint16   // off=48  size=2
	VlanID     uint16   // off=50  size=2  (802.1Q VLAN ID; 0 = untagged)
	VNI        uint32   // off=52  size=4  (VXLAN Network Identifier; 0 = non-VXLAN)
	OuterSrcIP [16]byte // off=56  size=16 (tunnel endpoint src; zero if non-VXLAN)
	OuterDstIP [16]byte // off=72  size=16 (tunnel endpoint dst)
	Bytes      uint64   // off=88  size=8
	Packets    uint64   // off=96  size=8
} // Total: 104 bytes
