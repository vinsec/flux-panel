package engine

import (
	"net"
	"slices"
)

// Both compilers enforce the same dynamic routing, source and pin contract.
func (a *AdvancedKernel) prepareRuntimeRules(rules map[string]Spec, addresses map[string][]string) map[string]Spec {
	routeLocal := routeLocalnetEnabled()
	a.runtimeErrors = map[string]string{}
	a.udpContracts = map[string]string{}
	a.localShapeWatch = false
	a.localShapePrereq = ""
	for _, s := range rules {
		if !s.Deleted && s.localTraffic() && s.Bandwidth.Enabled() {
			a.localShapeWatch = true
			a.localShapePrereq = localShapingProblem()
			if a.localShapePrereq == "" && !a.localProbeChecked {
				a.localProbeError = a.probeLocalShaping()
				a.localProbeChecked = true
			}
			break
		}
	}
	for id, s := range rules {
		if s.Deleted {
			continue
		}
		problem := s.localPathProblem(addresses, routeLocal)
		if s.preserveSource() && s.trafficPolicy().LocalTargets && slices.Contains(s.Protocols, "udp") {
			a.udpContracts[id] = problem
		}
		if problem == "" && s.localTraffic() && s.Bandwidth.Enabled() {
			problem = a.localShapePrereq
			if problem == "" {
				problem = a.localProbeError
			}
		}
		if problem == "" && s.Egress.Interface != "" {
			iface, err := net.InterfaceByName(s.Egress.Interface)
			if err != nil || iface.Flags&net.FlagUp == 0 {
				problem = "egress interface unavailable"
			} else {
				addresses, _ := iface.Addrs()
				assigned := map[string]bool{}
				for _, address := range addresses {
					ip, _, e := net.ParseCIDR(address.String())
					if e == nil {
						assigned[ip.String()] = true
					}
				}
				for _, source := range []string{s.Egress.SourceIPv4, s.Egress.SourceIPv6} {
					if source != "" && !assigned[source] {
						problem = "egress source address unavailable"
					}
				}
			}
		}
		if problem != "" {
			a.runtimeErrors[id] = problem
			s = cloneSpec(s)
			s.Enabled = false
			rules[id] = s
		}
	}
	return rules
}
