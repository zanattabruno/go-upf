package forwarder

// Optional, lab-only N6 scheduler. PFCP is the source of flow identity and
// bandwidth; there is no browser/controller shortcut that installs a class.
import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/wmnsk/go-pfcp/ie"
)

type labRuleSet map[uint16]map[uint32][]*ie.IE
type labGrant struct {
	SEID            uint64 `json:"seid"`
	PDRID           uint32 `json:"pdrId"`
	QERID           uint32 `json:"qerId"`
	QFI             uint8  `json:"qfi"`
	GBR             uint64 `json:"gbrKbps"`
	MBR             uint64 `json:"mbrKbps"`
	Source          string `json:"source"`
	Destination     string `json:"destination"`
	SourcePort      uint16 `json:"sourcePort"`
	DestinationPort uint16 `json:"destinationPort"`
	Class           int    `json:"class"`
}
type labHTB struct {
	mu        sync.Mutex
	dev       string
	statePath string
	capacity  uint64
	rules     map[uint64]labRuleSet
	grants    []labGrant
	staged    []labGrant
	fault     error
	command   func(...string) error
}

func tcCommand(args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	b, e := exec.CommandContext(ctx, "tc", args...).CombinedOutput()
	if e != nil {
		return fmt.Errorf("tc %v: %w: %s", args, e, b)
	}
	return nil
}
func openLabHTB() (*labHTB, error) {
	dev := os.Getenv("QOS_LAB_IFB")
	if dev == "" {
		return nil, nil
	}
	if _, e := os.Stat("/sys/class/net/" + dev); e != nil {
		return nil, e
	}
	h := &labHTB{dev: dev, statePath: os.Getenv("QOS_LAB_RULES_FILE"), capacity: 30000, rules: map[uint64]labRuleSet{}, command: tcCommand}
	if v := os.Getenv("QOS_LAB_CAPACITY_KBPS"); v != "" {
		n, e := strconv.ParseUint(v, 10, 64)
		if e != nil || n <= 1000 {
			return nil, fmt.Errorf("invalid lab capacity")
		}
		h.capacity = n
	}
	// Namespace/IFB ownership is established by the lab launcher.
	cmds := [][]string{{"qdisc", "replace", "dev", dev, "root", "handle", "1:", "htb", "default", "2"},
		{"class", "replace", "dev", dev, "parent", "1:", "classid", "1:1", "htb", "rate", fmt.Sprint(h.capacity) + "kbit", "ceil", fmt.Sprint(h.capacity) + "kbit", "burst", "32k", "cburst", "32k"},
		{"class", "replace", "dev", dev, "parent", "1:1", "classid", "1:2", "htb", "rate", "1000kbit", "ceil", fmt.Sprint(h.capacity) + "kbit", "burst", "32k", "cburst", "32k", "quantum", "1500"},
		{"qdisc", "replace", "dev", dev, "parent", "1:2", "handle", "2:", "fq_codel"}}
	for _, a := range cmds {
		if e := h.command(a...); e != nil {
			return nil, e
		}
	}
	return h, nil
}
func copyLabRules(old labRuleSet) labRuleSet {
	n := labRuleSet{}
	for typ, rs := range old {
		n[typ] = map[uint32][]*ie.IE{}
		for id, v := range rs {
			n[typ][id] = append([]*ie.IE(nil), v...)
		}
	}
	return n
}
func mergeLabIE(old, patch []*ie.IE) []*ie.IE {
	out := []*ie.IE{}
	types := map[uint16]bool{}
	for _, x := range patch {
		types[x.Type] = true
	}
	for _, x := range old {
		if !types[x.Type] {
			out = append(out, x)
		}
	}
	for _, x := range patch {
		if x.Type == ie.PDI {
			for _, v := range old {
				if v.Type == ie.PDI {
					x = ie.NewPDI(mergeLabIE(v.ChildIEs, x.ChildIEs)...)
					break
				}
			}
		}
		out = append(out, x)
	}
	return out
}
func stageLabRules(old labRuleSet, p *ModificationPlan) labRuleSet {
	n := copyLabRules(old)
	set := func(typ uint16, id uint32, x *ie.IE, op OpType) {
		if n[typ] == nil {
			n[typ] = map[uint32][]*ie.IE{}
		}
		if op == OpRemove {
			delete(n[typ], id)
		} else if op == OpUpdate {
			n[typ][id] = mergeLabIE(n[typ][id], x.ChildIEs)
		} else {
			n[typ][id] = x.ChildIEs
		}
	}
	for _, list := range [][]*PDRPlan{p.CreatePDRs, p.UpdatePDRs, p.RemovePDRs} {
		for _, x := range list {
			set(ie.CreatePDR, uint32(x.PDRID), x.OriginalIE, x.Op)
		}
	}
	for _, list := range [][]*QERPlan{p.CreateQERs, p.UpdateQERs, p.RemoveQERs} {
		for _, x := range list {
			set(ie.CreateQER, x.QERID, x.OriginalIE, x.Op)
		}
	}
	for _, list := range [][]*FARPlan{p.CreateFARs, p.UpdateFARs, p.RemoveFARs} {
		for _, x := range list {
			set(ie.CreateFAR, x.FARID, x.OriginalIE, x.Op)
		}
	}
	return n
}
func child(ies []*ie.IE, typ uint16) *ie.IE {
	for _, x := range ies {
		if x.Type == typ {
			return x
		}
	}
	return nil
}
func labGrants(seid uint64, rs labRuleSet) ([]labGrant, error) {
	out := []labGrant{}
	for id, ies := range rs[ie.CreatePDR] {
		pdi := child(ies, ie.PDI)
		if pdi == nil {
			continue
		}
		src := child(pdi.ChildIEs, ie.SourceInterface)
		if src == nil {
			continue
		}
		si, e := src.SourceInterface()
		if e != nil {
			return nil, e
		}
		if si != 1 {
			continue
		}
		for _, ref := range ies {
			if ref.Type != ie.QERID {
				continue
			}
			qid, e := ref.QERID()
			if e != nil {
				return nil, e
			}
			q := rs[ie.CreateQER][qid]
			gbr := child(q, ie.GBR)
			if gbr == nil {
				continue
			}
			g, e := gbr.GBRDL()
			if e != nil {
				return nil, e
			}
			if g == 0 {
				continue
			}
			mbr := child(q, ie.MBR)
			if mbr == nil {
				return nil, fmt.Errorf("GBR flow requires MBR")
			}
			b, e := mbr.MBRDL()
			if e != nil || b < g {
				return nil, fmt.Errorf("invalid GBR/MBR")
			}
			sdf := child(pdi.ChildIEs, ie.SDFFilter)
			if sdf == nil {
				return nil, fmt.Errorf("lab GBR needs an exact SDF filter")
			}
			f, e := sdf.SDFFilter()
			if e != nil {
				return nil, e
			}
			fd, e := ParseFlowDesc(f.FlowDescription)
			if e != nil {
				return nil, e
			}
			if fd.Proto != 17 || fd.Src == nil || fd.Dst == nil || len(fd.SrcPorts) != 1 || len(fd.DstPorts) != 1 || len(fd.SrcPorts[0]) != 1 || len(fd.DstPorts[0]) != 1 {
				return nil, fmt.Errorf("lab supports exact IPv4/UDP flow filters only")
			}
			ones, bits := fd.Src.Mask.Size()
			dstOnes, dstBits := fd.Dst.Mask.Size()
			if ones != 32 || bits != 32 || dstOnes != 32 || dstBits != 32 {
				return nil, fmt.Errorf("lab requires exact /32 IPv4 flow addresses")
			}
			var qfi uint8
			if v := child(q, ie.QFI); v != nil {
				qfi, _ = v.QFI()
			}
			out = append(out, labGrant{SEID: seid, PDRID: id, QERID: qid, QFI: qfi, GBR: g, MBR: b, Source: fd.Src.String(), Destination: fd.Dst.String(), SourcePort: fd.SrcPorts[0][0], DestinationPort: fd.DstPorts[0][0]})
		}
	}
	return out, nil
}
func (h *labHTB) desired(seid uint64, next labRuleSet) ([]labGrant, error) {
	out := []labGrant{}
	for id, rs := range h.rules {
		if id == seid {
			continue
		}
		g, e := labGrants(id, rs)
		if e != nil {
			return nil, e
		}
		out = append(out, g...)
	}
	g, e := labGrants(seid, next)
	if e != nil {
		return nil, e
	}
	out = append(out, g...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].SEID == out[j].SEID {
			return out[i].PDRID < out[j].PDRID
		}
		return out[i].SEID < out[j].SEID
	})
	var total uint64 = 1000
	seen := map[string]bool{}
	for i := range out {
		v := &out[i]
		total += v.GBR
		v.Class = 10 + i
		k := fmt.Sprintf("%s/%d/%s/%d", v.Source, v.SourcePort, v.Destination, v.DestinationPort)
		if seen[k] {
			return nil, fmt.Errorf("overlapping GBR flows")
		}
		seen[k] = true
	}
	if total > h.capacity {
		return nil, fmt.Errorf("lab capacity unavailable: requested %d Kbps including best effort, available %d", total, h.capacity)
	}
	return out, nil
}
func (h *labHTB) apply(grants []labGrant) error {
	// Replace matching classes first; delete only obsolete owned classes.
	for _, g := range grants {
		h.staged = append(h.staged, g)
		id := fmt.Sprintf("1:%x", g.Class)
		args := []string{"class", "replace", "dev", h.dev, "parent", "1:1", "classid", id, "htb", "rate", fmt.Sprint(g.GBR) + "kbit", "ceil", fmt.Sprint(g.MBR) + "kbit", "burst", "32k", "cburst", "32k", "quantum", "1500"}
		if e := h.command(args...); e != nil {
			return e
		}
		if e := h.command("qdisc", "replace", "dev", h.dev, "parent", id, "handle", fmt.Sprintf("%x:", g.Class), "fq_codel"); e != nil {
			return e
		}
		if e := h.command("filter", "replace", "dev", h.dev, "parent", "1:", "protocol", "ip", "pref", fmt.Sprint(g.Class), "handle", "1", "flower", "ip_proto", "udp", "src_ip", g.Source, "dst_ip", g.Destination, "src_port", fmt.Sprint(g.SourcePort), "dst_port", fmt.Sprint(g.DestinationPort), "classid", id); e != nil {
			return e
		}
	}
	seenClasses := map[int]bool{}
	for _, old := range append(append([]labGrant(nil), h.grants...), h.staged...) {
		if seenClasses[old.Class] {
			continue
		}
		seenClasses[old.Class] = true
		found := false
		for _, g := range grants {
			if g.Class == old.Class {
				found = true
			}
		}
		if !found {
			if e := h.command("filter", "del", "dev", h.dev, "parent", "1:", "protocol", "ip", "pref", fmt.Sprint(old.Class)); e != nil && !missingTC(e) {
				return e
			}
			if e := h.command("class", "del", "dev", h.dev, "classid", fmt.Sprintf("1:%x", old.Class)); e != nil && !missingTC(e) {
				return e
			}
		}
	}
	h.grants = grants
	h.staged = nil
	return nil
}
func (h *labHTB) snapshot() {
	if h.statePath == "" {
		return
	}
	b, _ := json.MarshalIndent(struct {
		At       time.Time  `json:"at"`
		Capacity uint64     `json:"capacityKbps"`
		Grants   []labGrant `json:"grants"`
	}{time.Now().UTC(), h.capacity, h.grants}, "", "  ")
	if os.WriteFile(h.statePath+".tmp", b, 0600) == nil {
		_ = os.Rename(h.statePath+".tmp", h.statePath)
	}
}

func (g *Gtp5g) ExecuteModificationPlan(p *ModificationPlan) (*ExecutionResult, error) {
	return g.executeLabPlan(p, false)
}
func (g *Gtp5g) ExecuteEstablishmentPlan(p *ModificationPlan) (*ExecutionResult, error) {
	return g.executeLabPlan(p, true)
}
func (g *Gtp5g) executeLabPlan(p *ModificationPlan, est bool) (*ExecutionResult, error) {
	native := g.executeModificationPlan
	if est {
		native = g.executeEstablishmentPlan
	}
	if g.lab == nil {
		return native(p)
	}
	h := g.lab
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.fault != nil {
		return nil, fmt.Errorf("lab scheduler requires reconciliation: %w", h.fault)
	}
	old := copyLabRules(h.rules[p.SEID])
	next := stageLabRules(old, p)
	grants, e := h.desired(p.SEID, next)
	if e != nil {
		return nil, e
	}
	result, e := native(p)
	if e == nil {
		e = h.apply(grants)
	}
	if e != nil {
		rollback := g.restoreLabRules(p.SEID, next, old)
		previous, _ := h.desired(p.SEID, old)
		tcErr := h.apply(previous)
		if rollback != nil || tcErr != nil {
			h.fault = fmt.Errorf("%w; rollback failed: kernel=%v scheduler=%v", e, rollback, tcErr)
			return nil, h.fault
		}
		return nil, e
	}
	h.rules[p.SEID] = next
	h.snapshot()
	return result, nil
}
func (g *Gtp5g) restoreLabRules(seid uint64, current, old labRuleSet) error {
	p := NewModificationPlan(seid)
	// Delete new PDRs first, then restore existing dependencies before PDRs.
	for id := range current[ie.CreatePDR] {
		if old[ie.CreatePDR][id] == nil {
			x, e := g.BuildRemovePDRPlan(seid, ie.NewRemovePDR(ie.NewPDRID(uint16(id))))
			if e != nil {
				return e
			}
			p.RemovePDRs = append(p.RemovePDRs, x)
		}
	}
	for id := range current[ie.CreateQER] {
		if old[ie.CreateQER][id] == nil {
			x, e := g.BuildRemoveQERPlan(seid, ie.NewRemoveQER(ie.NewQERID(id)))
			if e != nil {
				return e
			}
			p.RemoveQERs = append(p.RemoveQERs, x)
		}
	}
	for id := range current[ie.CreateFAR] {
		if old[ie.CreateFAR][id] == nil {
			x, e := g.BuildRemoveFARPlan(seid, ie.NewRemoveFAR(ie.NewFARID(id)))
			if e != nil {
				return e
			}
			p.RemoveFARs = append(p.RemoveFARs, x)
		}
	}
	for id, v := range old[ie.CreateFAR] {
		if current[ie.CreateFAR][id] == nil {
			x, e := g.BuildCreateFARPlan(seid, ie.NewCreateFAR(v...))
			if e != nil {
				return e
			}
			p.CreateFARs = append(p.CreateFARs, x)
		} else {
			x, e := g.BuildUpdateFARPlan(seid, ie.NewUpdateFAR(v...))
			if e != nil {
				return e
			}
			p.UpdateFARs = append(p.UpdateFARs, x)
		}
	}
	for id, v := range old[ie.CreateQER] {
		if current[ie.CreateQER][id] == nil {
			x, e := g.BuildCreateQERPlan(seid, ie.NewCreateQER(v...))
			if e != nil {
				return e
			}
			p.CreateQERs = append(p.CreateQERs, x)
		} else {
			x, e := g.BuildUpdateQERPlan(seid, ie.NewUpdateQER(v...))
			if e != nil {
				return e
			}
			p.UpdateQERs = append(p.UpdateQERs, x)
		}
	}
	for id, v := range old[ie.CreatePDR] {
		if current[ie.CreatePDR][id] == nil {
			x, e := g.BuildCreatePDRPlan(seid, ie.NewCreatePDR(v...))
			if e != nil {
				return e
			}
			p.CreatePDRs = append(p.CreatePDRs, x)
		} else {
			x, e := g.BuildUpdatePDRPlan(seid, ie.NewUpdatePDR(v...))
			if e != nil {
				return e
			}
			p.UpdatePDRs = append(p.UpdatePDRs, x)
		}
	}
	_, e := g.executeModificationPlan(p)
	return e
}

func missingTC(err error) bool {
	s := err.Error()
	return strings.Contains(s, "No such file") || strings.Contains(s, "Cannot find specified")
}
