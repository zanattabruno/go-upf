package forwarder

import (
	"fmt"
	"github.com/wmnsk/go-pfcp/ie"
	"strings"
	"sync"
	"testing"
)

func labRuleFixture(gbr uint64, port int) labRuleSet {
	flow := fmt.Sprintf("permit out 17 from 192.0.2.2 %d to 10.60.0.1 %d", port, port+800)
	return labRuleSet{ie.CreatePDR: {4: []*ie.IE{ie.NewPDRID(4), ie.NewPDI(ie.NewSourceInterface(1), ie.NewSDFFilter(flow, "", "", "", 0)), ie.NewQERID(3)}}, ie.CreateQER: {3: []*ie.IE{ie.NewQERID(3), ie.NewGBR(1, gbr), ie.NewMBR(1000, 25000), ie.NewQFI(2)}}}
}
func TestLabFlowMappingAndCapacity(t *testing.T) {
	h := &labHTB{capacity: 30000, rules: map[uint64]labRuleSet{}}
	r := labRuleFixture(20000, 5200)
	grants, e := h.desired(1, r)
	if e != nil {
		t.Fatal(e)
	}
	if len(grants) != 1 || grants[0].SourcePort != 5200 || grants[0].DestinationPort != 6000 || grants[0].GBR != 20000 || grants[0].MBR != 25000 || grants[0].QFI != 2 {
		t.Fatal(grants)
	}
	h.rules[1] = r
	if _, e = h.desired(2, labRuleFixture(20000, 5201)); e == nil {
		t.Fatal("overbooked 29 Mbps budget")
	}
	if _, e = h.desired(2, labRuleFixture(5000, 5200)); e == nil {
		t.Fatal("overlapping flow")
	}
	if _, e = h.desired(1, labRuleSet{}); e != nil {
		t.Fatal("removal failed", e)
	}
}
func TestLabConcurrentAdmission(t *testing.T) {
	h := &labHTB{capacity: 30000, rules: map[uint64]labRuleSet{}}
	accepted := 0
	var wg sync.WaitGroup
	for i := 1; i <= 2; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			h.mu.Lock()
			defer h.mu.Unlock()
			r := labRuleFixture(20000, 5200+id)
			if _, e := h.desired(uint64(id), r); e == nil {
				h.rules[uint64(id)] = r
				accepted++
			}
		}(i)
	}
	wg.Wait()
	if accepted != 1 {
		t.Fatal("admitted", accepted)
	}
}
func TestLabPartialSchedulerRollbackRemovesNewClass(t *testing.T) {
	var commands []string
	fail := true
	h := &labHTB{dev: "owned-ifb", command: func(a ...string) error {
		cmd := strings.Join(a, " ")
		commands = append(commands, cmd)
		if strings.Contains(cmd, "filter replace") && fail {
			fail = false
			return fmt.Errorf("injected failure")
		}
		return nil
	}}
	grant := labGrant{Class: 10, GBR: 20000, MBR: 25000, Source: "192.0.2.2/32", Destination: "10.60.0.1/32", SourcePort: 5200, DestinationPort: 6000}
	if h.apply([]labGrant{grant}) == nil {
		t.Fatal("missing injected error")
	}
	if e := h.apply(nil); e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(strings.Join(commands, "\n"), "class del dev owned-ifb classid 1:a") {
		t.Fatal("orphan class after rollback", commands)
	}
	if len(h.grants) != 0 || len(h.staged) != 0 {
		t.Fatal("reservation retained")
	}
}
