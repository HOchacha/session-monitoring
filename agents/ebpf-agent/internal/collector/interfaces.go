package collector

import (
	"net"
	"sort"
	"strings"
)

// defaultIncludePrefixes targets only tun devices (OpenVPN L3 tunnels).
// Other interface types (vnet, cloudbr, brvx, vxlan) are handled separately
// when per-VM eBPF deployment is introduced.
var defaultIncludePrefixes = []string{"tun"}

var defaultExcludePrefixes = []string{"lo", "docker", "veth", "virbr", "cni", "flannel", "kube"}

type InterfaceSelector struct {
	IncludePrefixes []string
	ExcludePrefixes []string
	RequireUp       bool
}

func NewDefaultSelector() InterfaceSelector {
	return InterfaceSelector{
		IncludePrefixes: defaultIncludePrefixes,
		ExcludePrefixes: defaultExcludePrefixes,
		RequireUp:       true,
	}
}

func DiscoverAttachInterfaces(sel InterfaceSelector) ([]string, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	includes := normalizePrefixes(sel.IncludePrefixes)
	excludes := normalizePrefixes(sel.ExcludePrefixes)
	if len(includes) == 0 {
		includes = normalizePrefixes(defaultIncludePrefixes)
	}

	picked := make([]string, 0, len(ifs))
	for _, ifc := range ifs {
		if sel.RequireUp && (ifc.Flags&net.FlagUp) == 0 {
			continue
		}
		name := strings.ToLower(strings.TrimSpace(ifc.Name))
		if name == "" {
			continue
		}
		if hasPrefix(name, excludes) {
			continue
		}
		if !hasPrefix(name, includes) {
			continue
		}
		picked = append(picked, ifc.Name)
	}

	sort.Strings(picked)
	return picked, nil
}

func normalizePrefixes(in []string) []string {
	out := make([]string, 0, len(in))
	for _, p := range in {
		t := strings.ToLower(strings.TrimSpace(p))
		if t == "" {
			continue
		}
		out = append(out, t)
	}
	return out
}

func hasPrefix(name string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}
