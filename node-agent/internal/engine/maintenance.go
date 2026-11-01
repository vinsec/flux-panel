package engine

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var MaintenanceFault func(string)

func maintenancePoint(stage string) {
	if MaintenanceFault != nil {
		MaintenanceFault(stage)
	}
}

type MaintenanceManifest struct {
	Version           int               `json:"version"`
	Epoch             string            `json:"epoch"`
	SourceFormat      int               `json:"sourceFormat"`
	CreatedAt         int64             `json:"createdAt"`
	PendingSettlement bool              `json:"pendingSettlement"`
	Files             map[string]string `json:"files"`
}
type MaintenanceResult struct {
	Backup            string `json:"backup"`
	Action            string `json:"action"`
	Paused            bool   `json:"paused"`
	PendingSettlement bool   `json:"pendingSettlement"`
}

var ownedNames = regexp.MustCompile(`^(FP_MARK|FP_PRE|FP_POST|FP_FWD|FP_CUP|FP_CDOWN|FP_ICMP|FP_IROOT|FP_N[0-9a-f]{1,3}|FP_I[0-9a-f]{1,3})$`)
var declaration = regexp.MustCompile(`(?m)^:([^ ]+) `)
var counterPrefix = regexp.MustCompile(`^\[([0-9]+):([0-9]+)\] `)

func legacyCounters(text string) map[string]uint64 {
	out := map[string]uint64{}
	for _, line := range strings.Split(text, "\n") {
		m := counterPrefix.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		f := strings.Fields(line)
		for i, v := range f {
			if v == "--comment" && i+1 < len(f) {
				name := strings.Trim(f[i+1], "\"")
				p := strings.Split(name, ":")
				if len(p) == 5 && p[0] == "flux" && p[1] == "v1" && serviceID.MatchString(p[2]) {
					out[name], _ = strconv.ParseUint(m[2], 10, 64)
				}
			}
		}
	}
	return out
}
func accumulate(s *State, c map[string]uint64) {
	if s.Totals == nil {
		s.Totals = map[string]Usage{}
	}
	if s.Last == nil {
		s.Last = map[string]uint64{}
	}
	for name := range s.Last {
		if _, ok := c[name]; !ok {
			s.Last[name] = 0
		}
	}
	for name, value := range c {
		p := strings.Split(name, ":")
		if len(p) != 5 {
			continue
		}
		u := s.Totals[p[2]]
		u.ID = p[2]
		last := s.Last[name]
		delta := value
		if value >= last {
			delta = value - last
		}
		switch p[4] {
		case "up":
			u.Up += delta
		case "down":
			u.Down += delta
		default:
			continue
		}
		s.Totals[p[2]] = u
		s.Last[name] = value
	}
}
func (k *IPTables) inventory() (map[string]string, map[string]string, error) {
	if k.Native != nil {
		if e := k.Native.ensure(); e != nil {
			return nil, nil, e
		}
		text, e := k.Native.run("", "list", "table", "inet", nativeTable)
		return map[string]string{"native-nft": text}, map[string]string{}, e
	}
	tables := map[string]string{}
	sets := map[string]string{}
	for _, table := range []string{"filter", "mangle", "nat"} {
		saved, e := k.run(k.Binary+"-save", "", "-c", "-t", table)
		if e != nil {
			return nil, nil, e
		}
		tables[table] = saved
	}
	names, e := k.run("ipset", "", "list", "-name")
	if e != nil {
		return nil, nil, e
	}
	for _, d := range setDefinitions {
		for _, name := range strings.Fields(names) {
			if name == d.Name {
				saved, e := k.readSet(name)
				if e != nil {
					return nil, nil, e
				}
				if !strings.Contains(saved, "flux-owner:v") {
					return nil, nil, fmt.Errorf("refusing to back up a foreign set %s", name)
				}
				sets[name] = saved
			}
		}
	}
	if k.P1 != nil {
		for _, name := range strings.Fields(names) {
			if strings.HasPrefix(name, "FP4_") || strings.HasPrefix(name, "FP6_") {
				saved, e := k.readSet(name)
				if e != nil {
					return nil, nil, e
				}
				if !strings.Contains(saved, advancedOwner) {
					return nil, nil, fmt.Errorf("foreign advanced set")
				}
				sets[name] = saved
			}
		}
	}
	return tables, sets, nil
}
func (k *IPTables) removeOwned(tables map[string]string, sets map[string]string) error {
	if e := k.protocolEngine().cleanup(); e != nil {
		return e
	}
	if k.Native != nil {
		return k.Native.cleanup()
	}
	base := map[string]string{}
	for name, saved := range sets {
		if !strings.HasPrefix(name, "FP4_") && !strings.HasPrefix(name, "FP6_") {
			base[name] = saved
		}
	}
	if e := k.removeBaseOwned(tables, base); e != nil {
		return e
	}
	if k.P1 != nil {
		return k.P1.cleanup()
	}
	return nil
}
func (k *IPTables) removeBaseOwned(tables map[string]string, sets map[string]string) error {
	// Inspect every reference before deleting anything. A foreign jump into an
	// owned chain is a conflict, never permission to edit that foreign rule.
	plans := map[string]string{}
	for table, saved := range tables {
		names := map[string]bool{}
		for _, m := range declaration.FindAllStringSubmatch(saved, -1) {
			if !ownedNames.MatchString(m[1]) {
				continue
			}
			if !strings.Contains(saved, "-A "+m[1]+" -m comment --comment flux-owner:v") && !strings.Contains(saved, "-A "+m[1]+" -m comment --comment \"flux-owner:v") {
				return fmt.Errorf("chain %s lacks ownership", m[1])
			}
			names[m[1]] = true
		}
		var body strings.Builder
		fmt.Fprintf(&body, "*%s\n", table)
		for _, name := range sortedNames(names) {
			fmt.Fprintf(&body, ":%s - [0:0]\n", name)
		}
		for _, line := range strings.Split(saved, "\n") {
			line = counterPrefix.ReplaceAllString(line, "")
			f := strings.Fields(line)
			if len(f) < 4 || f[0] != "-A" || names[f[1]] {
				continue
			}
			for i, v := range f {
				if (v == "-j" || v == "-g") && i+1 < len(f) && names[f[i+1]] {
					if !strings.Contains(line, "flux-hook:v") {
						return fmt.Errorf("foreign reference to %s", f[i+1])
					}
					fmt.Fprintln(&body, strings.Replace(line, "-A ", "-D ", 1))
					break
				}
			}
		}
		for _, name := range sortedNames(names) {
			fmt.Fprintf(&body, "-X %s\n", name)
		}
		body.WriteString("COMMIT\n")
		plans[table] = body.String()
	}
	for _, table := range []string{"mangle", "nat", "filter"} {
		if _, e := k.run(k.Binary+"-restore", plans[table], "--test", "--noflush", "--wait", "2"); e != nil {
			return e
		}
	}
	if _, e := k.run("conntrack", "", "-D", "-f", "ipv4", "--mark", mark); e != nil && !strings.Contains(e.Error(), "0 flow entries") {
		return e
	}
	for _, table := range []string{"mangle", "nat", "filter"} {
		if _, e := k.run(k.Binary+"-restore", plans[table], "--noflush", "--wait", "2"); e != nil {
			return e
		}
	}
	for name := range sets {
		if _, e := k.run("ipset", "", "destroy", name); e != nil {
			return e
		}
	}
	k.shape = ""
	k.controlShape = ""
	return nil
}
func sortedNames(m map[string]bool) []string {
	r := map[string]Spec{}
	for k := range m {
		r[k] = Spec{}
	}
	return keys(r)
}
func readMaintenanceState(path string) (State, error) {
	var s State
	b, e := os.ReadFile(path)
	if e != nil {
		return s, e
	}
	if e = json.Unmarshal(b, &s); e != nil {
		return s, e
	}
	if len(s.Epoch) != 32 || s.Sequence < 0 || s.Rules == nil || s.FormatVersion > 7 {
		return s, fmt.Errorf("invalid maintenance checkpoint")
	}
	return s, nil
}
func verifyBackup(dir string) (MaintenanceManifest, State, error) {
	var manifest MaintenanceManifest
	var s State
	b, e := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if e != nil {
		return manifest, s, e
	}
	if e = json.Unmarshal(b, &manifest); e != nil {
		return manifest, s, e
	}
	if manifest.Version != 1 {
		return manifest, s, fmt.Errorf("unsupported backup manifest")
	}
	for name, want := range manifest.Files {
		if filepath.Base(name) != name {
			return manifest, s, fmt.Errorf("invalid backup path")
		}
		b, e := os.ReadFile(filepath.Join(dir, name))
		if e != nil {
			return manifest, s, e
		}
		if digestBytes(b) != want {
			return manifest, s, fmt.Errorf("backup checksum mismatch: %s", name)
		}
	}
	s, e = readMaintenanceState(filepath.Join(dir, "state.json"))
	if e == nil && s.Epoch != manifest.Epoch {
		e = fmt.Errorf("backup epoch mismatch")
	}
	return manifest, s, e
}
func digestBytes(b []byte) string { return fmt.Sprintf("%x", sha256.Sum256(b)) }

// Maintain is intentionally disruptive and leaves desired forwards paused.
// Calls are made by the offline installer after stopping this namespace's Agent.
// settle must durably acknowledge usage AND pause the panel's desired state.
func Maintain(path, configPath, action, backupDir string, k *IPTables, offline bool, settle func(Report) (Acknowledgement, error)) (MaintenanceResult, error) {
	result := MaintenanceResult{Backup: backupDir, Action: action, Paused: true}
	if action != "backup" && action != "migrate" && action != "rollback" && action != "uninstall" && action != "settle" {
		return result, fmt.Errorf("unknown maintenance action")
	}
	if _, e := os.Stat(path + ".journal"); e == nil {
		return result, fmt.Errorf("recover the pending Agent transaction before maintenance")
	}
	state, e := readMaintenanceState(path)
	if e != nil {
		return result, e
	}
	backend := "iptables"
	if k.Native != nil {
		backend = "nftables"
	}
	priorBackend := state.KernelBackend
	if priorBackend == "" {
		priorBackend = "iptables"
	}
	if backend != priorBackend {
		return result, fmt.Errorf("maintenance must use the checkpoint's existing kernel backend; settle it before switching")
	}
	originalFormat := state.FormatVersion
	var source State
	var prior MaintenanceManifest
	if action == "rollback" {
		prior, source, e = verifyBackup(backupDir)
		if e != nil {
			return result, e
		}
		if source.Epoch != state.Epoch {
			return result, fmt.Errorf("cannot merge different accounting epochs")
		}
	}
	tables, sets, e := k.inventory()
	if e != nil {
		return result, e
	}
	if k.Native != nil {
		if e = k.ClaimEpoch(state.Epoch); e != nil {
			return result, e
		}
	}
	if _, ok := sets[metaSet]; ok {
		if e = k.ClaimEpoch(state.Epoch); e != nil {
			return result, e
		}
	}
	if k.P1 != nil && k.Native == nil {
		k.P1.epoch = state.Epoch
		if e = k.P1.initializeFromState(); e != nil {
			return result, e
		}
	}
	resumeIntent := map[string]json.RawMessage{}
	if b, err := os.ReadFile(path + ".maintenance"); err == nil {
		if err = json.Unmarshal(b, &resumeIntent); err != nil {
			return result, err
		}
		var priorAction, priorDir, priorEpoch string
		_ = json.Unmarshal(resumeIntent["action"], &priorAction)
		_ = json.Unmarshal(resumeIntent["backup"], &priorDir)
		_ = json.Unmarshal(resumeIntent["epoch"], &priorEpoch)
		if priorAction != action || priorDir != backupDir || priorEpoch != state.Epoch {
			return result, fmt.Errorf("different pending maintenance; resume its original action and backup path")
		}
		_ = json.Unmarshal(resumeIntent["sourceFormat"], &originalFormat)
	}
	if action != "rollback" && action != "settle" {
		if backupDir == "" {
			return result, fmt.Errorf("an explicit new backup directory is required")
		}
		preparedDir := false
		if entries, err := os.ReadDir(backupDir); err == nil {
			preparedDir = true
			for _, entry := range entries {
				if entry.IsDir() || (entry.Name() != "previous.bin" && entry.Name() != "previous.sha256" && entry.Name() != "previous-config.json" && entry.Name() != "previous-flux-agent.service" && entry.Name() != "previous-flux-kernel.service" && entry.Name() != "previous-units.sha256") {
					preparedDir = false
				}
			}
		}
		if e = os.Mkdir(backupDir, 0700); e != nil && !(os.IsExist(e) && (len(resumeIntent) > 0 || preparedDir)) {
			return result, e
		}
	}
	// This durable intent remains alongside the checkpoint through every failure.
	intent := map[string]any{"action": action, "backup": backupDir, "epoch": state.Epoch, "sourceFormat": originalFormat, "rules": state.Rules, "phase": "prepare"}
	if len(resumeIntent) > 0 {
		var originalRules map[string]Spec
		if e = json.Unmarshal(resumeIntent["rules"], &originalRules); e != nil {
			return result, e
		}
		intent["rules"] = originalRules
	}
	if e = atomicJSON(path+".maintenance", intent); e != nil {
		return result, e
	}
	maintenancePoint("prepare")
	if e = k.Quiesce(); e != nil {
		return result, e
	}
	maintenancePoint("quiesced")
	tables, sets, e = k.inventory()
	if e != nil {
		return result, e
	}
	counters := map[string]uint64{}
	if strings.Contains(tables["filter"], "flux:v1:") {
		counters = legacyCounters(tables["filter"])
	} else if _, ok := sets[upSet]; ok {
		counters, e = k.Snapshot()
		if e != nil {
			return result, e
		}
	}
	if _, err := os.Stat(path + ".counter-loss"); err == nil {
		for name, last := range state.Last {
			if counters[name] < last {
				state.Last[name] = counters[name]
			}
		}
		state.Leases = map[string]Lease{}
		state.Recovery = RecoveryInfo{true, state.LastDurableAt, "maintenance settled an interrupted kernel ledger"}
	}
	accumulate(&state, counters)
	state.Sequence++
	if state.BootID == "" {
		state.BootID = k.BootID()
	}
	state.LastDurableAt = time.Now().UnixMilli()
	for id, l := range state.Leases {
		l.Closed = true
		state.Leases[id] = l
	}
	if state.MaintenanceBootID != "" {
		state.BootID = state.MaintenanceBootID
	}
	state.MaintenanceBootID = state.BootID
	report := Report{BootID: state.BootID, Epoch: state.Epoch, Sequence: state.Sequence, Usage: []Usage{}, CheckpointAt: state.LastDurableAt}
	for _, id := range keys(state.Rules) {
		if u, ok := state.Totals[id]; ok {
			report.Usage = append(report.Usage, u)
		}
		if l, ok := state.Leases[id]; ok {
			report.Leases = append(report.Leases, LeaseUsage{l.Grant.ID, id, l.Grant.Generation, used(&state, id, l), true})
		}
	}
	pages := (len(report.Usage) + 9999) / 10000
	if pages < 1 {
		pages = 1
	}
	if pages > 1 {
		state.Sequence += int64(pages - 1)
		report.Sequence = state.Sequence
	}
	original := cloneState(state)
	if originalRules, ok := intent["rules"].(map[string]Spec); ok {
		for id, r := range original.Rules {
			if old, found := originalRules[id]; found {
				r.Enabled = old.Enabled
				original.Rules[id] = r
			}
		}
	}
	state.MaintenancePending = true
	for id, spec := range state.Rules {
		spec.Enabled = false
		state.Rules[id] = spec
	}
	if e = atomicJSON(path, state); e != nil {
		return result, e
	}
	maintenancePoint("checkpoint")
	var manifest MaintenanceManifest
	backupComplete := false
	if action != "rollback" && action != "settle" {
		if existing, _, err := verifyBackup(backupDir); err == nil {
			manifest = existing
			backupComplete = true
		}
	}
	if action != "rollback" && action != "settle" && !backupComplete {
		manifest = MaintenanceManifest{Version: 1, Epoch: state.Epoch, SourceFormat: originalFormat, CreatedAt: time.Now().UnixMilli(), PendingSettlement: true, Files: map[string]string{}}
		files := map[string][]byte{}
		files["state.json"], _ = json.Marshal(original)
		files["final-usage.json"], _ = json.Marshal(report)
		if files["config.json"], e = os.ReadFile(configPath); e != nil {
			return result, e
		}
		if k.P1 != nil {
			extras, err := k.P1.backupExtras()
			if err != nil {
				return result, err
			}
			for name, b := range extras {
				files[name] = b
			}
		}
		for table, saved := range tables {
			files[table+".rules"] = []byte(saved)
		}
		for name, saved := range sets {
			files[name+".ipset"] = []byte(saved)
		}
		for name, b := range files {
			if e = atomicBytes(filepath.Join(backupDir, name), b); e != nil {
				return result, e
			}
			manifest.Files[name] = digestBytes(b)
		}
		if e = atomicJSON(filepath.Join(backupDir, "manifest.json"), manifest); e != nil {
			return result, e
		}
	}
	maintenancePoint("backedup")
	if !offline {
		ack, e := settleMaintenancePages(report, settle)
		if e != nil {
			return result, fmt.Errorf("settlement failed; guard and durable intent retained: %w", e)
		}
		if ack.Epoch != report.Epoch || ack.Sequence != report.Sequence || !ack.MaintenanceAccepted {
			return result, fmt.Errorf("panel did not confirm maintenance pause")
		}
		state.MaintenancePending = false
		state.Leases = map[string]Lease{}
		state.LeaseAcks = map[string]uint64{}
		state.MaintenanceBootID = ""
		if action != "rollback" && action != "settle" {
			manifest.PendingSettlement = false
			if e = atomicJSON(filepath.Join(backupDir, "manifest.json"), manifest); e != nil {
				return result, e
			}
		}
	}
	maintenancePoint("settled")
	if action == "migrate" || action == "rollback" || action == "uninstall" || action == "backup" || action == "settle" {
		if e = k.removeOwned(tables, sets); e != nil {
			return result, e
		}
		maintenancePoint("cleanup")
		if action == "rollback" {
			for id, u := range state.Totals {
				old := source.Totals[id]
				if u.Up > old.Up {
					old.Up = u.Up
				}
				if u.Down > old.Down {
					old.Down = u.Down
				}
				old.ID = id
				source.Totals[id] = old
			}
			source.Sequence = state.Sequence
			source.MaintenancePending = state.MaintenancePending
			source.MaintenanceBootID = state.MaintenanceBootID
			source.Leases = state.Leases
			source.FormatVersion = prior.SourceFormat
			state = source
		} else if action == "migrate" {
			state.FormatVersion = requiredStateFormat(state.Rules)
			if state.KernelBackend == "nftables" {
				state.FormatVersion = max(state.FormatVersion, 6)
			}
			state.KernelID = ""
			state.BootID = ""
		}
		state.Last = map[string]uint64{}
		state.CounterLast = map[string]uint64{}
		state.KernelID = ""
		state.BootID = ""
		for id, spec := range state.Rules {
			spec.Enabled = false
			state.Rules[id] = spec
		}
		if e = atomicJSON(path, state); e != nil {
			return result, e
		}
		if action == "migrate" {
			if e = k.Initialize(); e != nil {
				return result, e
			}
			m, e := New(path, k)
			if e != nil {
				return result, e
			}
			state = m.state
		}
	}
	maintenancePoint("installed")
	if e = atomicJSON(path, state); e != nil {
		return result, e
	}
	state.AccountingBlocked = false
	if e = atomicJSON(path, state); e != nil {
		return result, e
	}
	if !state.MaintenancePending {
		if e = k.Activate(); e != nil {
			return result, e
		}
	}
	if _, err := os.Stat(path + ".counter-loss"); err == nil {
		if e = removeDurable(path + ".counter-loss"); e != nil {
			return result, e
		}
	}
	if e = removeDurable(path + ".maintenance"); e != nil {
		return result, e
	}
	result.PendingSettlement = state.MaintenancePending
	return result, nil
}
