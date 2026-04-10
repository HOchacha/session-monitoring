package collector

import (
	"fmt"
	"log"
	"net"

	bpfgen "ebpf-agent/internal/bpf"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// Attachments holds loaded BPF objects and tc filter handles so they can
// be cleaned up on shutdown.
type Attachments struct {
	Objects *bpfgen.FlowObjects
	Filters []netlink.Filter
	Reader  *ringbuf.Reader
}

// LoadAndAttach loads the BPF program, attaches it as a tc-ingress
// classifier on every interface in ifaces, and opens a ringbuf reader.
func LoadAndAttach(ifaces []string) (*Attachments, error) {
	var objs bpfgen.FlowObjects
	if err := bpfgen.LoadFlowObjects(&objs, &ebpf.CollectionOptions{}); err != nil {
		return nil, fmt.Errorf("load BPF objects: %w", err)
	}

	att := &Attachments{Objects: &objs}

	for _, name := range ifaces {
		if err := attachTC(name, objs.HandleIngress, att); err != nil {
			log.Printf("WARN: skip %s: %v", name, err)
			continue
		}
		log.Printf("attached tc/ingress on %s", name)
	}

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		att.Close()
		return nil, fmt.Errorf("open ringbuf reader: %w", err)
	}
	att.Reader = rd

	return att, nil
}

// attachTC creates a clsact qdisc (if absent) and adds a BPF tc filter
// for ingress on the given interface.
func attachTC(ifname string, prog *ebpf.Program, att *Attachments) error {
	ifc, err := net.InterfaceByName(ifname)
	if err != nil {
		return fmt.Errorf("interface %q: %w", ifname, err)
	}

	link, err := netlink.LinkByIndex(ifc.Index)
	if err != nil {
		return fmt.Errorf("link %q: %w", ifname, err)
	}

	// Ensure clsact qdisc exists.
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: ifc.Index,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}
	if err := netlink.QdiscReplace(qdisc); err != nil {
		return fmt.Errorf("add clsact qdisc on %s: %w", ifname, err)
	}

	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    netlink.HANDLE_MIN_INGRESS,
			Handle:    0x1,
			Protocol:  unix.ETH_P_ALL,
			Priority:  1,
		},
		Fd:           prog.FD(),
		Name:         "ebpf-agent/ingress",
		DirectAction: true,
	}
	if err := netlink.FilterReplace(filter); err != nil {
		return fmt.Errorf("attach BPF filter on %s: %w", ifname, err)
	}

	att.Filters = append(att.Filters, filter)
	return nil
}

// Close detaches all tc filters and releases BPF resources.
func (a *Attachments) Close() {
	if a.Reader != nil {
		a.Reader.Close()
	}
	for _, f := range a.Filters {
		if err := netlink.FilterDel(f); err != nil {
			log.Printf("WARN: remove filter: %v", err)
		}
	}
	if a.Objects != nil {
		a.Objects.Close()
	}
}
