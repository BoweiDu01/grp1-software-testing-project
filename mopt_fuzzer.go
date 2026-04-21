package main

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// ---------------------------------------------------------------------------
// Constants & Configuration
// ---------------------------------------------------------------------------

const (
	HangTimeoutSec = 30.0
	HighEnergy     = 40
	StableEnergy   = 15
	MediumEnergy   = 10
	LowEnergy      = 5
	DefaultEnergy  = 10
	MinQueueSize   = 5
)

var (
	InterestInts    = []int64{0, 1, -1, 127, 128, 255, 256, 32767, 32768, 65535, 65536, 2147483647, 2147483648, -2147483648, 4294967295, 4294967296}
	InterestStrings = []string{"", "A", "AAAA", "\x00", "%s%n%d", "\r\n", "javascript:void(0)", "admin", "true", "1", "[]", "{}", "Infinity", "NaN"}
	InterestValues  = []string{"0", "1", "127", "128", "255", "256", "65535", "4294967295", "-1", "0xFFFF", "abc", "null", "{}", "Infinity", "-Infinity", "NaN"}
	Separators      = []string{".", ":", "/", "%", ",", ";", " ", "\t", "{", "}", "[", "]"}
	Dictionary      = []string{"::", "0.0.0.0", "127.0.0.1", "ff02::1", "::ffff:192.168.1.1", "{}", "[]", "null", "/24", "/128", "%eth0"}
)

var SurgicalOps = []Mutation{
	{"bit_nudge", func(data []byte, _ [][]byte, r *rand.Rand) []byte {
		if len(data) == 0 { return data }
		res := make([]byte, len(data))
		copy(res, data)
		pos := r.Intn(len(res))
		res[pos] ^= 1 << uint(r.Intn(8))
		return res
	}},
	{"byte_nudge", mutByteNudge},
	{"arith_nudge", func(data []byte, _ [][]byte, r *rand.Rand) []byte {
		parts := tokenize(data)
		indices := []int{}
		for i, t := range parts {
			if i%2 == 0 && t != "" {
				if _, err := strconv.ParseInt(t, 10, 64); err == nil {
					indices = append(indices, i)
				}
			}
		}
		if len(indices) == 0 { return data }
		idx := indices[r.Intn(len(indices))]
		val, _ := strconv.ParseInt(parts[idx], 10, 64)
		val += int64([]int{-1, 1}[r.Intn(2)])
		parts[idx] = strconv.FormatInt(val, 10)
		return reconstruct(parts)
	}},
}

// ---------------------------------------------------------------------------
// Data Structures
// ---------------------------------------------------------------------------

type DriverConfig struct {
	Name         string   `json:"name"`
	Target       string   `json:"target"`
	Interpreter  string   `json:"interpreter"`
	Engine       string   `json:"engine"`
	InputMode    string   `json:"input_mode"`
	Argv         []string `json:"argv"`
	Type         string   `json:"type"`
	Timeout      float64  `json:"timeout"`
	SeedsDir     string   `json:"seeds_dir"`
}

type SeedEntry struct {
	Data   []byte
	Energy int
	Tier   int
	Source string
	Sig    string
	Picks  int
}

var (
	queueMutex sync.Mutex
)

type FuzzTask struct {
	Seed *SeedEntry
}

type FuzzResult struct {
	Ops     []string
	Mutated []byte
	ExecRes *ExecutionResult
	Seed    *SeedEntry
	GenerationTimeSec float64
}

type Logger struct {
	sync.Mutex
	Writer *csv.Writer
	File   *os.File
}

func NewLogger(driverName string) *Logger {
	logDir := "logs"
	os.MkdirAll(logDir, 0755)
	logPath := filepath.Join(logDir, fmt.Sprintf("%s_go_%d.csv", driverName, time.Now().Unix()))
	f, err := os.Create(logPath)
	if err != nil {
		fmt.Printf("Error creating log file: %v\n", err)
		return nil
	}
	w := csv.NewWriter(f)
	header := []string{
		"timestamp", "iteration", "is_interesting", "tier", "reason", "op_name",
		"seed_text", "mutated_text", "seed_b64", "mutated_b64", "status",
		"exit_code", "timed_out", "elapsed_sec", "generation_time_sec", "command", "bug_type",
		"exception", "message", "file", "line", "input_hash",
	}
	w.Write(header)
	w.Flush()
	return &Logger{Writer: w, File: f}
}

func (l *Logger) Log(idx int, tier int, reason string, ops []string, seedData, mutated []byte, res *ExecutionResult, genTimeSec float64, config DriverConfig) {
	if l == nil {
		return
	}
	l.Lock()
	defer l.Unlock()

	status := "success"
	if res.TimedOut {
		status = "hang"
	} else if res.IsError {
		status = "crash"
	}

	opName := strings.Join(ops, "->")
	isInteresting := 0
	if tier > 0 {
		isInteresting = 1
	}

	tierStr := ""
	if tier > 0 {
		tierStr = fmt.Sprintf("tier_%d", tier)
	}

	cleanText := func(b []byte) string {
		s := strings.Map(func(r rune) rune {
			if (r < 32 && r != '\n' && r != '\t' && r != '\r') || r == 127 {
				return -1
			}
			return r
		}, string(b))
		return strings.TrimSpace(s)
	}

	seedTextClean := cleanText(seedData)
	mutatedTextClean := cleanText(mutated)

	cmdParts := []string{config.Target}
	if config.Interpreter != "" {
		cmdParts = []string{config.Interpreter, config.Target}
	}
	for _, arg := range config.Argv {
		cmdParts = append(cmdParts, strings.ReplaceAll(arg, "@@", mutatedTextClean))
	}

	bugType, exc, line := "", "", 0
	if res.TimedOut {
		bugType = "hang"
		exc = "Timeout"
	} else if tier > 0 || res.IsError {
		bugType, exc, line = classifyBug(res.Stdout, res.Stderr)
	}

	msg := ""
	cleanStderr := cleanText([]byte(res.Stderr))
	lines := strings.Split(cleanStderr, "\n")
	if len(lines) > 0 {
		msg = lines[0]
		if len(msg) > 200 {
			msg = msg[:200]
		}
	}

	h := md5.Sum(mutated)
	row := []string{
		strconv.FormatInt(time.Now().Unix(), 10),
		strconv.Itoa(idx),
		strconv.Itoa(isInteresting),
		tierStr,
		reason,
		opName,
		seedTextClean,
		mutatedTextClean,
		base64.StdEncoding.EncodeToString(seedData),
		base64.StdEncoding.EncodeToString(mutated),
		status,
		strconv.Itoa(res.ExitCode),
		strconv.FormatBool(res.TimedOut),
		fmt.Sprintf("%.3f", res.ExecTimeMs/1000.0),
		fmt.Sprintf("%.6f", genTimeSec),
		strings.Join(cmdParts, " "),
		bugType,
		exc,
		msg,
		"",
		strconv.Itoa(line),
		hex.EncodeToString(h[:]),
	}
	l.Writer.Write(row)
	l.Writer.Flush()
}

type ExecutionResult struct {
	Stdout      string
	Stderr      string
	IsError     bool
	ExecTimeMs  float64
	TimedOut    bool
	ExitCode    int
}

type Mutation struct {
	Name string
	Func func([]byte, [][]byte, *rand.Rand) []byte
}

// ---------------------------------------------------------------------------
// Mutation Manager (Multi-Swarm MOPT Scheduler)
// ---------------------------------------------------------------------------

const (
	NumSwarms = 5
	W         = 0.9 // Inertia weight
	C1        = 0.5 // Cognitive coefficient
	C2        = 0.5 // Social coefficient
)

type Swarm struct {
	Weights    []float64
	Velocity   []float64
	LocalBest  []float64
	LBestEff   float64
	Rewards    float64
	Count      int
}

type MutationManager struct {
	sync.Mutex
	BlindOps    []Mutation
	ASTEngine   *ASTMutationEngine
	
	Swarms      []*Swarm
	GlobalBest  []float64
	GBestEff    float64
	
	CurrentSwarmIdx int
	TotalIter       int
	
	ModeStats   map[string]*StatEntry // modeName -> stats
	ActiveModes []string
	ModeWeights []float64

	BugOpHits   map[string]int // "opName:bugSig" -> count
}

type StatEntry struct {
	Rewards float64
	Count   int
}

func NewMutationManager(blindOps []Mutation, astEngine *ASTMutationEngine) *MutationManager {
	mm := &MutationManager{
		BlindOps:  blindOps,
		ASTEngine: astEngine,
		ModeStats: make(map[string]*StatEntry),
		BugOpHits: make(map[string]int),
	}

	numOps := len(blindOps)
	mm.Swarms = make([]*Swarm, NumSwarms)
	for i := 0; i < NumSwarms; i++ {
		s := &Swarm{
			Weights:   make([]float64, numOps),
			Velocity:  make([]float64, numOps),
			LocalBest: make([]float64, numOps),
		}
		// Initialize with random/uniform weights
		total := 0.0
		for j := 0; j < numOps; j++ {
			s.Weights[j] = 0.1 + rand.Float64()
			total += s.Weights[j]
			s.Velocity[j] = 0.0
		}
		for j := 0; j < numOps; j++ {
			s.Weights[j] /= total
			s.LocalBest[j] = s.Weights[j]
		}
		mm.Swarms[i] = s
	}

	mm.GlobalBest = make([]float64, numOps)
	copy(mm.GlobalBest, mm.Swarms[0].Weights)

	mm.ActiveModes = []string{"blind"}
	if astEngine != nil {
		mm.ActiveModes = append(mm.ActiveModes, "tree")
	}

	for _, mode := range mm.ActiveModes {
		mm.ModeStats[mode] = &StatEntry{Rewards: 1, Count: 2}
	}

	if astEngine != nil {
		mm.ModeStats["tree"].Rewards = 50
		mm.ModeStats["tree"].Count = 1
	}

	mm.updateModeWeights()
	return mm
}

func (mm *MutationManager) updateModeWeights() {
	// Assumes mm.Lock() is held
	modeRates := make([]float64, len(mm.ActiveModes))
	totalModeRate := 0.0
	for i, mode := range mm.ActiveModes {
		rate := mm.ModeStats[mode].Rewards / float64(mm.ModeStats[mode].Count)
		modeRates[i] = rate
		totalModeRate += rate
	}

	mm.ModeWeights = make([]float64, len(mm.ActiveModes))
	totalModeFinal := 0.0
	for i := range modeRates {
		w := 0.1
		if totalModeRate > 0 {
			w = modeRates[i] / totalModeRate
			if w < 0.1 {
				w = 0.1
			}
		}
		mm.ModeWeights[i] = w
		totalModeFinal += w
	}
	for i := range mm.ModeWeights {
		mm.ModeWeights[i] /= totalModeFinal
	}
}

func (mm *MutationManager) UpdatePSO(r *rand.Rand) {
	mm.Lock()
	defer mm.Unlock()
	for _, s := range mm.Swarms {
		if s.Count == 0 {
			continue
		}
		eff := s.Rewards / float64(s.Count)
		
		// Update Local Best
		if eff > s.LBestEff {
			s.LBestEff = eff
			copy(s.LocalBest, s.Weights)
		}
		
		// Update Global Best
		if eff > mm.GBestEff {
			mm.GBestEff = eff
			if mm.GlobalBest == nil {
				mm.GlobalBest = make([]float64, len(mm.BlindOps))
			}
			copy(mm.GlobalBest, s.Weights)
		}

		// Velocity & Position Update
		total := 0.0
		for j := 0; j < len(mm.BlindOps); j++ {
			r1, r2 := r.Float64(), r.Float64()
			s.Velocity[j] = W*s.Velocity[j] + 
				C1*r1*(s.LocalBest[j]-s.Weights[j]) + 
				C2*r2*(mm.GlobalBest[j]-s.Weights[j])
			
			s.Weights[j] += s.Velocity[j]
			if s.Weights[j] < 0.01 {
				s.Weights[j] = 0.01
			}
			total += s.Weights[j]
		}
		// Normalize
		for j := 0; j < len(mm.BlindOps); j++ {
			s.Weights[j] /= total
		}
		
		// Reset stats for next pilot period
		s.Rewards = 0
		s.Count = 0
	}
}

func weightedSelect(weights []float64, r *rand.Rand) int {
	rv := r.Float64()
	cumulative := 0.0
	for i, w := range weights {
		cumulative += w
		if rv <= cumulative {
			return i
		}
	}
	return len(weights) - 1
}

func (mm *MutationManager) SelectAndMutate(data []byte, seeds [][]byte, energy int, r *rand.Rand) ([]string, []byte) {
	mm.Lock()
	mm.TotalIter++
	if mm.TotalIter % (100 * NumSwarms) == 0 {
		mm.Unlock()
		mm.UpdatePSO(r)
		mm.Lock()
	}
	
	mm.CurrentSwarmIdx = (mm.TotalIter / 10) % NumSwarms
	s := mm.Swarms[mm.CurrentSwarmIdx]
	
	localWeights := make([]float64, len(s.Weights))
	copy(localWeights, s.Weights)
	localModeWeights := make([]float64, len(mm.ModeWeights))
	copy(localModeWeights, mm.ModeWeights)
	mm.Unlock()

	numMuts := 1
	if r.Float64() < 0.2 {
		numMuts = r.Intn(max(1, min(16, energy/5))) + 1
	}
	appliedOps := []string{}
	mutated := make([]byte, len(data))
	copy(mutated, data)

	for i := 0; i < numMuts; i++ {
		opIdx := weightedSelect(localWeights, r)
		op := mm.BlindOps[opIdx]
		modeIdx := weightedSelect(localModeWeights, r)
		mode := mm.ActiveModes[modeIdx]

		var nextMutated []byte
		actualMode := mode

		if mode == "tree" && mm.ASTEngine != nil {
			nextMutated = mm.ASTEngine.Mutate(mutated, op.Func, seeds, r)
		} else {
			nextMutated = op.Func(mutated, seeds, r)
			actualMode = "blind"
		}
		
		if nextMutated != nil {
			mutated = nextMutated
			appliedOps = append(appliedOps, actualMode+":"+op.Name)
		}
	}

	return appliedOps, mutated
}

func (mm *MutationManager) RecordResult(fullName string, reward float64, bugSig string) {
	mm.Lock()
	defer mm.Unlock()

	parts := strings.SplitN(fullName, ":", 2)
	if len(parts) != 2 {
		return
	}
	mode, opName := parts[0], parts[1]

	// Operator Decay: If this operator keeps finding the same bug, its reward decays.
	if bugSig != "" {
		key := opName + ":" + bugSig
		mm.BugOpHits[key]++
		hits := mm.BugOpHits[key]
		if hits > 1 {
			// Decay reward exponentially after the first hit
			for i := 0; i < hits-1; i++ {
				reward *= 0.5
			}
		}
	}

	s := mm.Swarms[mm.CurrentSwarmIdx]
	s.Count++
	s.Rewards += reward

	if entry, ok := mm.ModeStats[mode]; ok {
		entry.Count++
		entry.Rewards += reward
	}
	mm.updateModeWeights()
}

func (mm *MutationManager) GetStatsSummary() string {
	mm.Lock()
	defer mm.Unlock()
	s := mm.Swarms[mm.CurrentSwarmIdx]
	type opWeight struct {
		name   string
		weight float64
	}
	weights := []opWeight{}
	for i, op := range mm.BlindOps {
		weights = append(weights, opWeight{op.Name, s.Weights[i]})
	}
	sort.Slice(weights, func(i, j int) bool {
		return weights[i].weight > weights[j].weight
	})

	parts := []string{}
	for i := 0; i < 3 && i < len(weights); i++ {
		parts = append(parts, fmt.Sprintf("%s(%.0f%%)", weights[i].name, weights[i].weight*100))
	}

	modeParts := []string{}
	for i, mode := range mm.ActiveModes {
		modeParts = append(modeParts, fmt.Sprintf("%s(%.0f%%)", strings.ToUpper(mode), mm.ModeWeights[i]*100))
	}

	return fmt.Sprintf("Swarm[%d] | %s | Mode: %s", mm.CurrentSwarmIdx, strings.Join(parts, " | "), strings.Join(modeParts, " "))
}

// ---------------------------------------------------------------------------
// Blind Mutation Operators
// ---------------------------------------------------------------------------

func mutBitFlip(data []byte, _ [][]byte, r *rand.Rand) []byte {
	if len(data) == 0 {
		return []byte{byte(r.Intn(256))}
	}
	res := make([]byte, len(data))
	copy(res, data)
	pos := r.Intn(len(res))
	res[pos] ^= 1 << uint(r.Intn(8))
	return res
}

func mutByteFlip(data []byte, _ [][]byte, r *rand.Rand) []byte {
	if len(data) == 0 {
		return []byte{byte(r.Intn(256))}
	}
	res := make([]byte, len(data))
	copy(res, data)
	pos := r.Intn(len(res))
	res[pos] ^= 0xFF
	return res
}

func mutByteNudge(data []byte, _ [][]byte, r *rand.Rand) []byte {
	if len(data) == 0 {
		return data
	}
	res := make([]byte, len(data))
	copy(res, data)
	pos := r.Intn(len(res))
	delta := []int{-1, 1}[r.Intn(2)]
	res[pos] = byte((int(res[pos]) + delta + 256) % 256)
	return res
}

func mutSplice(data []byte, seeds [][]byte, r *rand.Rand) []byte {
	if len(seeds) == 0 || len(data) < 2 {
		return data
	}
	other := seeds[r.Intn(len(seeds))]
	if len(other) == 0 {
		return data
	}
	cut1 := r.Intn(len(data))
	cut2 := r.Intn(len(other))
	res := append([]byte{}, data[:cut1]...)
	res = append(res, other[cut2:]...)
	return res
}

func tokenize(data []byte) []string {
	text := string(data)
	re := regexp.MustCompile(`([.:/%,; \t\\|{} [\]])`)
	matches := re.FindAllStringIndex(text, -1)
	result := []string{}
	last := 0
	for _, m := range matches {
		result = append(result, text[last:m[0]])
		result = append(result, text[m[0]:m[1]])
		last = m[1]
	}
	result = append(result, text[last:])
	return result
}

func reconstruct(parts []string) []byte {
	var buf bytes.Buffer
	for _, p := range parts {
		buf.WriteString(p)
	}
	return buf.Bytes()
}

func mutTokenArith(data []byte, _ [][]byte, r *rand.Rand) []byte {
	parts := tokenize(data)
	indices := []int{}
	for i, t := range parts {
		if i%2 == 1 || t == "" {
			continue
		}
		if _, err := strconv.ParseInt(t, 10, 64); err == nil {
			indices = append(indices, i)
		} else if _, err := strconv.ParseInt(t, 16, 64); err == nil {
			indices = append(indices, i)
		}
	}
	if len(indices) == 0 {
		return data
	}
	idx := indices[r.Intn(len(indices))]
	t := parts[idx]
	
	val, err := strconv.ParseInt(t, 10, 64)
	isHex := false
	if err != nil {
		val, err = strconv.ParseInt(t, 16, 64)
		isHex = true
	}
	if err == nil {
		val += int64(r.Intn(71) - 35)
		if isHex {
			parts[idx] = fmt.Sprintf("%x", uint16(val))
		} else {
			parts[idx] = strconv.FormatInt(val, 10)
		}
	}
	return reconstruct(parts)
}

func mutTokenSub(data []byte, _ [][]byte, r *rand.Rand) []byte {
	parts := tokenize(data)
	indices := []int{}
	for i, t := range parts {
		if i%2 == 0 && t != "" {
			indices = append(indices, i)
		}
	}
	if len(indices) == 0 {
		return data
	}
	idx := indices[r.Intn(len(indices))]
	parts[idx] = InterestValues[r.Intn(len(InterestValues))]
	return reconstruct(parts)
}

func mutTokenSplice(data []byte, seeds [][]byte, r *rand.Rand) []byte {
	if len(seeds) == 0 {
		return data
	}
	other := seeds[r.Intn(len(seeds))]
	partsA := tokenize(data)
	partsB := tokenize(other)
	
	indicesA := []int{}
	for i, t := range partsA {
		if i%2 == 0 && t != "" {
			indicesA = append(indicesA, i)
		}
	}
	indicesB := []int{}
	for i, t := range partsB {
		if i%2 == 0 && t != "" {
			indicesB = append(indicesB, i)
		}
	}
	if len(indicesA) == 0 || len(indicesB) == 0 {
		return data
	}
	partsA[indicesA[r.Intn(len(indicesA))]] = partsB[indicesB[r.Intn(len(indicesB))]]
	return reconstruct(partsA)
}

func mutTokenDelDup(data []byte, _ [][]byte, r *rand.Rand) []byte {
	parts := tokenize(data)
	indices := []int{}
	for i, t := range parts {
		if i%2 == 0 && t != "" {
			indices = append(indices, i)
		}
	}
	if len(indices) == 0 {
		return data
	}
	idx := indices[r.Intn(len(indices))]
	if r.Float64() < 0.5 {
		if idx+1 < len(parts) {
			parts = append(parts[:idx], parts[idx+2:]...)
		} else {
			parts = parts[:idx]
		}
	} else {
		if idx+1 < len(parts) {
			toDup := parts[idx : idx+2]
			res := append([]string{}, parts[:idx+2]...)
			res = append(res, toDup...)
			res = append(res, parts[idx+2:]...)
			parts = res
		} else {
			parts = append(parts, parts[idx])
		}
	}
	return reconstruct(parts)
}

func mutSepChaos(data []byte, _ [][]byte, r *rand.Rand) []byte {
	parts := tokenize(data)
	indices := []int{}
	for i := range parts {
		if i%2 == 1 {
			indices = append(indices, i)
		}
	}
	if len(indices) == 0 {
		return data
	}
	idx := indices[r.Intn(len(indices))]
	if r.Float64() < 0.5 {
		parts[idx] = Separators[r.Intn(len(Separators))]
	} else {
		parts[idx] = parts[idx] + parts[idx]
	}
	return reconstruct(parts)
}

func mutLeadingZeros(data []byte, _ [][]byte, r *rand.Rand) []byte {
	parts := tokenize(data)
	indices := []int{}
	for i, t := range parts {
		if i%2 == 0 {
			if _, err := strconv.Atoi(t); err == nil {
				indices = append(indices, i)
			}
		}
	}
	if len(indices) == 0 {
		return data
	}
	idx := indices[r.Intn(len(indices))]
	parts[idx] = strings.Repeat("0", r.Intn(4)+1) + parts[idx]
	return reconstruct(parts)
}

func mutTokenStretch(data []byte, _ [][]byte, r *rand.Rand) []byte {
	parts := tokenize(data)
	indices := []int{}
	for i := range parts {
		if i%2 == 0 && parts[i] != "" {
			indices = append(indices, i)
		}
	}
	if len(indices) == 0 {
		return data
	}
	idx := indices[r.Intn(len(indices))]
	parts[idx] = strings.Repeat(parts[idx], r.Intn(50)+50)
	if len(reconstruct(parts)) > 1000000 {
		return data
	}
	return reconstruct(parts)
}

func mutNastyByteInject(data []byte, _ [][]byte, r *rand.Rand) []byte {
	nasty := [][]byte{
		{0xed, 0xa0, 0x80},
		{0xc0, 0xaf},
		{0x00},
		{0xfe, 0xff},
		{0xff, 0xff, 0xff, 0xff},
	}
	payload := nasty[r.Intn(len(nasty))]
	pos := r.Intn(len(data) + 1)
	res := append([]byte{}, data[:pos]...)
	res = append(res, payload...)
	res = append(res, data[pos:]...)
	return res
}

func mutDictInject(data []byte, _ [][]byte, r *rand.Rand) []byte {
	payload := Dictionary[r.Intn(len(Dictionary))]
	pos := r.Intn(len(data) + 1)
	res := make([]byte, 0, len(data)+len(payload))
	res = append(res, data[:pos]...)
	res = append(res, []byte(payload)...)
	res = append(res, data[pos:]...)
	return res
}

func mutLengthBoundary(data []byte, _ [][]byte, r *rand.Rand) []byte {
	parts := tokenize(data)
	indices := []int{}
	for i := range parts {
		if i%2 == 0 && parts[i] != "" {
			indices = append(indices, i)
		}
	}
	if len(indices) == 0 {
		return data
	}
	idx := indices[r.Intn(len(indices))]
	boundaries := []int{128, 255, 256, 512, 1000, 1024, 4096, 32768, 65535, 65536}
	targetLen := boundaries[r.Intn(len(boundaries))]
	
	if len(parts[idx]) == 0 {
		parts[idx] = "A"
	}
	parts[idx] = strings.Repeat(parts[idx][:1], targetLen)
	
	if len(reconstruct(parts)) > 1000000 {
		return data
	}
	return reconstruct(parts)
}

func mutValueBoundary(data []byte, _ [][]byte, r *rand.Rand) []byte {
	parts := tokenize(data)
	indices := []int{}
	for i, t := range parts {
		if i%2 == 0 && t != "" {
			if _, err := strconv.ParseInt(t, 10, 64); err == nil {
				indices = append(indices, i)
			}
		}
	}
	if len(indices) == 0 {
		return data
	}
	idx := indices[r.Intn(len(indices))]
	boundaries := []string{
		"0", "-1", "255", "256", "32767", "32768", "65535", "65536",
		"2147483647", "2147483648", "4294967295", "4294967296",
		"9223372036854775807", "-9223372036854775808",
		"NaN", "Infinity", "-Infinity",
	}
	parts[idx] = boundaries[r.Intn(len(boundaries))]
	return reconstruct(parts)
}

// ---------------------------------------------------------------------------
// AST Mutation Engine (JSON)
// ---------------------------------------------------------------------------

type ASTMutationEngine struct {
	TypeName string
}

func (ae *ASTMutationEngine) Mutate(data []byte, opFunc func([]byte, [][]byte, *rand.Rand) []byte, seeds [][]byte, r *rand.Rand) []byte {
	if ae.TypeName == "json" {
		var v interface{}
		if err := json.Unmarshal(data, &v); err == nil {
			mutated := ae.mutateValue(v, opFunc, seeds, r)
			if res, err := json.Marshal(mutated); err == nil {
				return res
			}
		}
	}
	return ae._mutateGenericTree(data, opFunc, seeds, r)
}

func (ae *ASTMutationEngine) _mutateGenericTree(data []byte, opFunc func([]byte, [][]byte, *rand.Rand) []byte, seeds [][]byte, r *rand.Rand) []byte {
	tokens := tokenize(data)
	if len(tokens) <= 1 {
		return opFunc(data, seeds, r)
	}

	indices := []int{}
	for i, t := range tokens {
		if i%2 == 0 && t != "" {
			indices = append(indices, i)
		}
	}
	if len(indices) == 0 {
		return opFunc(data, seeds, r)
	}

	action := []string{"swap", "delete", "dup", "mutate_val", "wrap", "mass_dup"}[r.Intn(6)]
	idx := indices[r.Intn(len(indices))]

	switch action {
	case "swap":
		if len(indices) >= 2 {
			idx2 := indices[r.Intn(len(indices))]
			for idx2 == idx {
				idx2 = indices[r.Intn(len(indices))]
			}
			tokens[idx], tokens[idx2] = tokens[idx2], tokens[idx]
		}
	case "delete":
		if idx+1 < len(tokens) {
			tokens = append(tokens[:idx], tokens[idx+2:]...)
		} else {
			tokens = tokens[:idx]
		}
	case "dup":
		if idx+1 < len(tokens) {
			toDup := []string{tokens[idx], tokens[idx+1]}
			res := append([]string{}, tokens[:idx+2]...)
			res = append(res, toDup...)
			res = append(res, tokens[idx+2:]...)
			tokens = res
		} else {
			tokens = append(tokens, tokens[idx])
		}
	case "mass_dup":
		item := tokens[idx]
		if idx+1 < len(tokens) {
			item += tokens[idx+1]
		}
		count := r.Intn(450) + 50
		if len(item)*count < 1000000 {
			tokens[idx] = strings.Repeat(item, count)
		}
	case "wrap":
		if r.Float64() < 0.5 {
			tokens[idx] = "[" + tokens[idx] + "]"
		} else {
			tokens[idx] = "{" + tokens[idx] + "}"
		}
	case "mutate_val":
		token := tokens[idx]
		inferredType := "string"
		if token == "true" || token == "false" || token == "null" {
			inferredType = "bool"
		} else if _, err := strconv.ParseInt(token, 10, 64); err == nil {
			inferredType = "int"
		} else if _, err := strconv.ParseFloat(token, 64); err == nil {
			inferredType = "float"
		}

		if r.Float64() < 0.3 {
			if inferredType == "bool" {
				tokens[idx] = []string{"true", "false", "null"}[r.Intn(3)]
			} else if inferredType == "int" {
				tokens[idx] = strconv.FormatInt(InterestInts[r.Intn(len(InterestInts))], 10)
			} else if inferredType == "float" {
				floats := []string{"0.0", "-1.0", "1e20", "1e-20"}
				tokens[idx] = floats[r.Intn(len(floats))]
			} else {
				tokens[idx] = InterestStrings[r.Intn(len(InterestStrings))]
			}
		} else {
			mutVal := opFunc([]byte(token), seeds, r)
			tokens[idx] = string(mutVal)
		}
	}
	return reconstruct(tokens)
}

func (ae *ASTMutationEngine) mutateValue(v interface{}, opFunc func([]byte, [][]byte, *rand.Rand) []byte, seeds [][]byte, r *rand.Rand) interface{} {
	switch val := v.(type) {
	case map[string]interface{}:
		if len(val) == 0 {
			return val
		}
		if r.Float64() < 0.3 {
			actions := []string{"swap", "delete", "dup", "wrap_dict", "wrap_list", "type_confusion", "deep_wrap"}
			action := actions[r.Intn(len(actions))]
			keys := make([]string, 0, len(val))
			for k := range val {
				keys = append(keys, k)
			}
			switch action {
			case "swap":
				if len(keys) >= 2 {
					k1, k2 := keys[0], keys[1]
					val[k1], val[k2] = val[k2], val[k1]
				}
			case "delete":
				delete(val, keys[r.Intn(len(keys))])
			case "dup":
				k := keys[r.Intn(len(keys))]
				newKey := k + "_dup"
				if len(Dictionary) > 0 && r.Float64() < 0.5 {
					newKey = Dictionary[r.Intn(len(Dictionary))]
				}
				val[newKey] = val[k]
			case "wrap_dict":
				newKey := "injected"
				if len(Dictionary) > 0 && r.Float64() < 0.5 {
					newKey = Dictionary[r.Intn(len(Dictionary))]
				}
				return map[string]interface{}{newKey: val}
			case "wrap_list":
				return []interface{}{val}
			case "type_confusion":
				confusions := []interface{}{true, false, nil, 1337, "confusion", []interface{}{}, map[string]interface{}{}}
				return confusions[r.Intn(len(confusions))]
			case "deep_wrap":
				depth := r.Intn(1500) + 500
				var curr interface{} = val
				for i := 0; i < depth; i++ {
					if r.Float64() < 0.5 {
						curr = map[string]interface{}{"a": curr}
					} else {
						curr = []interface{}{curr}
					}
				}
				return curr
			}
		} else {
			keys := make([]string, 0, len(val))
			for k := range val {
				keys = append(keys, k)
			}
			k := keys[r.Intn(len(keys))]
			val[k] = ae.mutateValue(val[k], opFunc, seeds, r)
		}
		return val
	case []interface{}:
		if len(val) == 0 {
			return val
		}
		if r.Float64() < 0.3 {
			idx := r.Intn(len(val))
			actions := []string{"swap", "delete", "dup", "type_confusion"}
			action := actions[r.Intn(len(actions))]
			switch action {
			case "swap":
				idx2 := r.Intn(len(val))
				val[idx], val[idx2] = val[idx2], val[idx]
			case "delete":
				val = append(val[:idx], val[idx+1:]...)
			case "dup":
				val = append(val, nil)
				copy(val[idx+1:], val[idx:])
				val[idx] = val[idx+1]
			case "type_confusion":
				confusions := []interface{}{true, false, nil, 1337, "confusion", []interface{}{}, map[string]interface{}{}}
				return confusions[r.Intn(len(confusions))]
			}
		} else {
			idx := r.Intn(len(val))
			val[idx] = ae.mutateValue(val[idx], opFunc, seeds, r)
		}
		return val
	default:
		if r.Float64() < 0.3 {
			switch val.(type) {
			case bool: return r.Float64() < 0.5
			case float64: return float64(InterestInts[r.Intn(len(InterestInts))])
			case string: return InterestStrings[r.Intn(len(InterestStrings))]
			}
		}
		s := fmt.Sprintf("%v", val)
		mutated := opFunc([]byte(s), seeds, r)
		if _, ok := val.(string); ok {
			var escaped string
			jsonBytes, _ := json.Marshal(string(mutated))
			json.Unmarshal(jsonBytes, &escaped)
			return escaped
		}
		return string(mutated)
	}
}

// ---------------------------------------------------------------------------
// Evaluator & Executor
// ---------------------------------------------------------------------------

func classifyBug(stdout, stderr string) (string, string, int) {
	combined := stdout + "\n" + stderr
	// 1. match internal tuple format ('category', <class 'exc'>, ...)
	summaryPattern := regexp.MustCompile(`\('(\w+)',\s*<class\s*'([^']+)'>,\s*.*?,.*?, (\d+)\)`)
	match := summaryPattern.FindStringSubmatch(combined)
	if match != nil {
		return match[1], match[2], 0
	}

	// 2. match custom target application markers (e.g. "A performance bug has been triggered: ...")
	customPattern := regexp.MustCompile(`[Aa] (\w+) bug has been triggered: (.*)`)
	cMatch := customPattern.FindStringSubmatch(combined)
	if cMatch != nil {
		cat := strings.ToLower(cMatch[1])
		exc := strings.TrimSpace(cMatch[2])
		if len(exc) > 50 { exc = exc[:50] } // Truncate long messages
		return cat, exc, 0
	}

	// 3. match standard Python exception line at start of a line (Generic)
	// Example: "IndexError: list index out of range"
	pyExcPattern := regexp.MustCompile(`(?m)^([a-zA-Z_]\w*(?:\.[a-zA-Z_]\w*)*): (.*)`)
	pyMatch := pyExcPattern.FindStringSubmatch(combined)
	if pyMatch != nil {
		fullExc := pyMatch[1]
		parts := strings.Split(fullExc, ".")
		exc := parts[len(parts)-1] // Just the class name
		cat := "python_exception"
		return cat, exc, 0
	}

	if strings.Contains(combined, "ParseException") {
		return "invalidity", "ParseException", 0
	}
	
	// 4. Ultimate Fallback for Uniqueness (e.g. Segfaults, OS aborts)
	// Use first 40 chars of error output to ensure uniqueness
	fallback := strings.TrimSpace(stderr)
	if fallback == "" { fallback = strings.TrimSpace(stdout) }
	if fallback != "" {
		// Clean it up
		fallback = strings.ReplaceAll(fallback, "\n", " ")
		if len(fallback) > 40 { fallback = fallback[:40] }
		return "raw_crash", fallback, 0
	}

	return "unknown", "UnknownBug", 0
}

type Evaluator struct {
	sync.Mutex
	CrashHitCounts map[string]int
	SeenHashes     map[string]bool
	ExecTimes      []float64
	AvgExecTime    float64
}

func (e *Evaluator) Evaluate(res *ExecutionResult, data []byte) (int, string, string) {
	h := sha256.Sum256(data)
	dataHash := hex.EncodeToString(h[:])

	e.Lock()
	defer e.Unlock()

	// 1. Check for Crashes
	if res.IsError {
		cat, exc, _ := classifyBug(res.Stdout, res.Stderr)
		sig := hex.EncodeToString(sha256.New().Sum([]byte(fmt.Sprintf("%s:%s", cat, exc))))
		
		e.CrashHitCounts[sig]++
		count := e.CrashHitCounts[sig]
		
		if count == 1 {
			return 1, "new_crash", sig
		}
		if count <= 128 && (count&(count-1)) == 0 {
			return 2, "stable_crash", sig
		}
		return 0, "", sig
	}

	// 2. Prevent duplicate processing of the same mutation data
	if e.SeenHashes[dataHash] {
		return 0, "", ""
	}
	e.SeenHashes[dataHash] = true

	// 3. Tier 3: Performance Outliers (Interestingness feedback)
	e.ExecTimes = append(e.ExecTimes, res.ExecTimeMs)
	if len(e.ExecTimes) > 50 {
		// Calculate a rolling average for the last 50 runs
		sum := 0.0
		startIdx := len(e.ExecTimes) - 50
		for _, t := range e.ExecTimes[startIdx:] {
			sum += t
		}
		e.AvgExecTime = sum / 50.0

		// If it takes > 5x the average, it's a performance outlier
		if res.ExecTimeMs > e.AvgExecTime*5.0 && e.AvgExecTime > 0.1 {
			return 3, "performance_outlier", dataHash
		}
	}

	return 0, "", ""
}

func executeTarget(ctx context.Context, config DriverConfig, inputData []byte, workerDir string, originalDir string) *ExecutionResult {
    start := time.Now()
    os.MkdirAll(workerDir, 0755)

    inputStr := strings.TrimSpace(string(inputData))
    args := []string{}
    for _, arg := range config.Argv {
        parsedArg := strings.ReplaceAll(arg, "@@", inputStr)
        if strings.Contains(parsedArg, "\x00") {
            return &ExecutionResult{IsError: false, Stdout: "", Stderr: "Skipped: Null byte in argv"}
        }
        args = append(args, parsedArg)
    }

    var cmd *exec.Cmd
    if config.Interpreter != "" {
        cmd = exec.CommandContext(ctx, config.Interpreter, append([]string{config.Target}, args...)...)
    } else {
        cmd = exec.CommandContext(ctx, config.Target, args...)
    }

    cmd.Dir = workerDir
    if config.Interpreter != "" {
        cmd.Env = append(os.Environ(), fmt.Sprintf("PYTHONPATH=%s", originalDir))
    } else {
        cmd.Env = os.Environ()
    }
    
    // Setpgid ensures the process and any children it spawns are in the same process group.
    cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

    outPath := filepath.Join(workerDir, "stdout.log")
    errPath := filepath.Join(workerDir, "stderr.log")
    outFile, _ := os.Create(outPath)
    errFile, _ := os.Create(errPath)

    cmd.Stdout = outFile
    cmd.Stderr = errFile

    err := cmd.Start()
    if err != nil {
        outFile.Close()
        errFile.Close()
        return &ExecutionResult{IsError: false, Stdout: "", Stderr: fmt.Sprintf("Fuzzer Execution Error: %v", err)}
    }

    // cleanup kills the entire process group
    cleanup := func() {
        if cmd.Process != nil {
            pgid, err := syscall.Getpgid(cmd.Process.Pid)
            if err == nil {
                syscall.Kill(-pgid, syscall.SIGKILL)
            }
        }
    }

    done := make(chan error, 1)
    go func() {
        done <- cmd.Wait()
    }()

    timeout := time.Duration(config.Timeout * float64(time.Second))
    if config.Timeout == 0 {
        timeout = HangTimeoutSec * time.Second
    }

    res := &ExecutionResult{}
    select {
    case <-ctx.Done():
        cleanup()
        return &ExecutionResult{TimedOut: false, IsError: false}
    case <-time.After(timeout):
        cleanup()
        res.TimedOut = true
        res.IsError = true
    case err := <-done:
        if err != nil {
            res.IsError = true
            if exiterr, ok := err.(*exec.ExitError); ok {
                if status, ok := exiterr.Sys().(syscall.WaitStatus); ok {
                    res.ExitCode = status.ExitStatus()
                }
            }
        }
    }

    outFile.Close()
    errFile.Close()

    outBytes, _ := os.ReadFile(outPath)
    errBytes, _ := os.ReadFile(errPath)
    res.Stdout = string(outBytes)
    res.Stderr = string(errBytes)
    res.ExecTimeMs = float64(time.Since(start).Milliseconds())

    combined := res.Stdout + "\n" + res.Stderr
    hasBugMarkers := strings.Contains(combined, "Bug Type") || 
                     strings.Contains(combined, "Exception:") || 
                     strings.Contains(combined, "Traceback") || 
                     strings.Contains(strings.ToLower(combined), "bug has been triggered")

    if hasBugMarkers {
        res.IsError = true
        // If it's a bug, we don't treat it as a "hang" in the final reporting tier logic, 
        // even if it took a long time.
        res.TimedOut = false 
    }

    return res
}

func extractDictionary(ctx context.Context, target string) {
	cmd := exec.CommandContext(ctx, "strings", target)
	out, err := cmd.Output()
	if err != nil {
		return
	}
	lines := strings.Split(string(out), "\n")
	dictMap := make(map[string]bool)
	for _, d := range Dictionary {
		dictMap[d] = true
	}
	count := 0
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if len(line) >= 4 && len(line) <= 32 {
			if !dictMap[line] {
				dictMap[line] = true
				Dictionary = append(Dictionary, line)
				count++
			}
		}
	}
	if count > 0 {
		fmt.Printf("[*] Extracted %d strings from target for dictionary\n", count)
	}
}

func cullQueue(queue *[]*SeedEntry) {
	queueMutex.Lock()
	defer queueMutex.Unlock()
	if len(*queue) < 100 {
		return
	}
	sort.Slice(*queue, func(i, j int) bool {
		if (*queue)[i].Tier != (*queue)[j].Tier {
			return (*queue)[i].Tier < (*queue)[j].Tier
		}
		if (*queue)[i].Energy != (*queue)[j].Energy {
			return (*queue)[i].Energy > (*queue)[j].Energy
		}
		return (*queue)[i].Picks < (*queue)[j].Picks
	})
	if len(*queue) > 500 {
		*queue = (*queue)[:500]
	}
}

func consolidateLogs() {
    fmt.Println("[*] Consolidating logs and cleaning up environments...")

    fuzzEnvDir := "fuzz_env"
    masterLogDir := "logs"
    os.MkdirAll(masterLogDir, 0755)

    masterTracebacksPath := filepath.Join(masterLogDir, "tracebacks.log")
    masterCSVPath := filepath.Join(masterLogDir, "bug_counts.csv")

    tbFile, err := os.OpenFile(masterTracebacksPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
    if err != nil {
        fmt.Printf("Error opening master tracebacks: %v\n", err)
        return
    }
    defer tbFile.Close()

    mergedCounts := make(map[string]int)

    filepath.Walk(fuzzEnvDir, func(path string, info os.FileInfo, err error) error {
        if err != nil || info.IsDir() {
            return nil
        }

        // Check for Tracebacks (Matches any traceback.log in any subfolder)
        if strings.HasSuffix(path, "tracebacks.log") {
            data, readErr := os.ReadFile(path)
            if readErr == nil {
                tbFile.Write([]byte(fmt.Sprintf("\n--- Source: %s ---\n", path)))
                tbFile.Write(data)
            }
        }

        // Check for CSVs (Matches any bug_counts.csv in any subfolder)
        if strings.HasSuffix(path, "bug_counts.csv") {
            f, openErr := os.Open(path)
            if openErr == nil {
                reader := csv.NewReader(f)
                records, _ := reader.ReadAll()
                f.Close()

                for i, row := range records {
                    if i == 0 || len(row) < 6 { continue } 
                    // Use columns 0-4 as the unique bug signature
                    key := strings.Join(row[:5], "|||")
                    count, _ := strconv.Atoi(row[5])
                    mergedCounts[key] += count
                }
            }
        }
        return nil
    })

    type bugRow struct {
        data  []string
        count int
    }
    var sortedRows []bugRow

    for key, count := range mergedCounts {
        sortedRows = append(sortedRows, bugRow{
            data:  strings.Split(key, "|||"),
            count: count,
        })
    }
	
    sort.Slice(sortedRows, func(i, j int) bool {
        if sortedRows[i].data[0] != sortedRows[j].data[0] {
            return sortedRows[i].data[0] < sortedRows[j].data[0]
        }
        return sortedRows[i].data[1] < sortedRows[j].data[1]
    })

    // 3. Write the finalized, sorted CSV
    if len(sortedRows) > 0 {
        csvFile, err := os.Create(masterCSVPath)
        if err == nil {
            defer csvFile.Close()
            writer := csv.NewWriter(csvFile)
            
            // Write Header
            writer.Write([]string{"bug_type", "exc_type", "exc_message", "filename", "lineno", "count"})
            
            for _, row := range sortedRows {
                fullRow := append(row.data, strconv.Itoa(row.count))
                writer.Write(fullRow)
            }
            writer.Flush()
        }
    }

    os.RemoveAll(fuzzEnvDir) 
}

func main() {
	driverPath := flag.String("driver", "", "Path to the JSON driver file")
	maxIterations := flag.Int("max-iterations", 10000, "Maximum number of iterations")
	seed := flag.Int64("seed", 42, "Random seed")
	numWorkers := flag.Int("workers", runtime.NumCPU(), "Number of concurrent workers")
	flag.Parse()

	if *driverPath == "" {
		fmt.Println("Usage: mopt_fuzzer --driver <path> [--max-iterations <n>] [--seed <n>] [--workers <n>]")
		return
	}

	rand.Seed(*seed)
	dispatcherRand := rand.New(rand.NewSource(*seed))

	data, err := os.ReadFile(*driverPath)
	if err != nil {
		fmt.Printf("Error reading driver: %v\n", err)
		return
	}

	var config DriverConfig
	if err := json.Unmarshal(data, &config); err != nil {
		fmt.Printf("Error parsing driver: %v\n", err)
		return
	}

	if config.Interpreter != "" {
		if abs, err := filepath.Abs(config.Interpreter); err == nil {
			config.Interpreter = abs
		}
	}
	if config.Target != "" {
		if abs, err := filepath.Abs(config.Target); err == nil {
			config.Target = abs
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-stop
		fmt.Println("\n[*] Stop requested...")
		cancel()
	}()

	extractDictionary(ctx, config.Target)

	var astEngine *ASTMutationEngine
	if config.Type != "" {
		astEngine = &ASTMutationEngine{TypeName: config.Type}
	}

	blindOps := []Mutation{
		{"bit_flip", mutBitFlip},
		{"byte_flip", mutByteFlip},
		{"byte_nudge", mutByteNudge},
		{"splice", mutSplice},
		{"token_arith", mutTokenArith},
		{"token_sub", mutTokenSub},
		{"token_splice", mutTokenSplice},
		{"token_del_dup", mutTokenDelDup},
		{"sep_chaos", mutSepChaos},
		{"leading_zeros", mutLeadingZeros},
		{"token_stretch", mutTokenStretch},
		{"nasty_byte", mutNastyByteInject},
		{"dict_inject", mutDictInject},
		{"length_boundary", mutLengthBoundary},
		{"value_boundary", mutValueBoundary},
	}

	mm := NewMutationManager(blindOps, astEngine)
	eval := &Evaluator{
		CrashHitCounts: make(map[string]int),
		SeenHashes:     make(map[string]bool),
		ExecTimes:      make([]float64, 0),
	}
	logger := NewLogger(config.Name)
	if logger != nil {
		defer logger.File.Close()
	}

	seedQueue := []*SeedEntry{}
	seedsDir := config.SeedsDir
	if seedsDir == "" {
		seedsDir = filepath.Join("corpus", config.Type)
	}

	files, _ := os.ReadDir(seedsDir)
	for _, f := range files {
		if !f.IsDir() {
			d, _ := os.ReadFile(filepath.Join(seedsDir, f.Name()))
			seedQueue = append(seedQueue, &SeedEntry{Data: d, Energy: DefaultEnergy})
		}
	}

	if len(seedQueue) == 0 {
		seedQueue = append(seedQueue, &SeedEntry{Data: []byte("127.0.0.1"), Energy: DefaultEnergy})
	}

	campaignStartTime := time.Now()
	campaignStartISO := campaignStartTime.Format(time.RFC3339)
	fmt.Printf("[*] Fuzzer started | Target: %s | Workers: %d | Seeds: %d\n", config.Target, *numWorkers, len(seedQueue))

	tasks := make(chan FuzzTask, *numWorkers*2)
	results := make(chan FuzzResult, *numWorkers*2)

	exploitSemaphore := make(chan struct{}, 2)

	var wg sync.WaitGroup

	originalDir, _ := os.Getwd()

	for w := 0; w < *numWorkers; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			workerDir, _ := filepath.Abs(fmt.Sprintf("fuzz_env/worker_%d", workerID))
			r := rand.New(rand.NewSource(*seed + int64(workerID) + 1))
			for task := range tasks {
				if ctx.Err() != nil { continue }
				queueMutex.Lock()
				seedsData := [][]byte{}
				for _, s := range seedQueue {
					seedsData = append(seedsData, s.Data)
				}
				queueMutex.Unlock()

				genStart := time.Now()
				ops, mutated := mm.SelectAndMutate(task.Seed.Data, seedsData, task.Seed.Energy, r)
				genTimeSec := time.Since(genStart).Seconds()

				res := executeTarget(ctx, config, mutated, workerDir, originalDir)
				results <- FuzzResult{Ops: ops, Mutated: mutated, ExecRes: res, Seed: task.Seed, GenerationTimeSec: genTimeSec}
			}
		}(w)
	}

	var count int64 = 0
	resultsDone := make(chan bool)
	go func() {
		for res := range results {
			tier, sigType, sig := eval.Evaluate(res.ExecRes, res.Mutated)
			
			// Weighted Reward Calculation
			reward := 0.0
			if tier == 1 {
				cat, exc, _ := classifyBug(res.ExecRes.Stdout, res.ExecRes.Stderr)
				if cat == "invalidity" || exc == "ParseException" {
					reward = 1.0
				} else {
					reward = 100.0
				}
			} else if tier == 2 {
				reward = 10.0
			} else if tier == 3 {
				reward = 50.0 // Performance outliers are very rewarding
			}

			for _, op := range res.Ops {
				mm.RecordResult(op, reward, sig)
			}

			currentCount := int(atomic.AddInt64(&count, 1))
			logger.Log(currentCount, tier, sigType, res.Ops, res.Seed.Data, res.Mutated, res.ExecRes, res.GenerationTimeSec, config)

			if tier > 0 {
				cat, exc, _ := classifyBug(res.ExecRes.Stdout, res.ExecRes.Stderr)

				if tier == 1 {
					// Vulnerability Refinement Queueing: 
					// Add hard crashes back to queue with High Energy, deduplicated by Exception Name.
					if cat != "invalidity" && exc != "ParseException" {
						queueMutex.Lock()
						exists := false
						for _, s := range seedQueue {
							if s.Tier == 1 && s.Sig == exc {
								exists = true
								break
							}
						}
						if !exists {
							seedQueue = append(seedQueue, &SeedEntry{
								Data: res.Mutated, Energy: HighEnergy, Tier: 1, Sig: exc,
							})
						}
						queueMutex.Unlock()
					}

					fmt.Printf("  [+] Exploitation Phase Triggered for %s (%s)\n", sig, exc)
					wg.Add(1)
					go func(exploCtx context.Context, baseData []byte, baseSig string, baseSeedData []byte, c int) {
						defer wg.Done()

						exploitSemaphore <- struct{}{}
                        defer func() { <-exploitSemaphore }()

						exploitDir, _ := filepath.Abs(fmt.Sprintf("fuzz_env/exploit_%d", time.Now().UnixNano()))
						r := rand.New(rand.NewSource(*seed + int64(c)*1337))

						for j := 0; j < 500; j++ {
							if exploCtx.Err() != nil { break }
							op := SurgicalOps[r.Intn(len(SurgicalOps))]
							
							genStart := time.Now()
							mutated := op.Func(baseData, [][]byte{}, r)
							genTimeSec := time.Since(genStart).Seconds()
							execRes := executeTarget(exploCtx, config, mutated, exploitDir, originalDir)
							lTier, _, lSig := eval.Evaluate(execRes, mutated)
							
							lReward := 0.0
							if lTier == 1 {
								lCat, lExc, _ := classifyBug(execRes.Stdout, execRes.Stderr)
								if lCat == "invalidity" || lExc == "ParseException" {
									lReward = 1.0
								} else {
									lReward = 100.0
								}
							} else if lTier == 2 {
								lReward = 10.0
							}
							
							logger.Log(c, lTier, "exploitation", []string{"exploitation", op.Name}, baseSeedData, mutated, execRes, genTimeSec, config)
							if lTier > 0 {
								mm.RecordResult("blind:"+op.Name, lReward, lSig)
								if lTier == 1 {
									fmt.Printf("      [*] Local exploitation found NEW bug: %s\n", lSig)
								}
							}
						}
					}(ctx, res.Mutated, sig, res.Seed.Data, currentCount)
				} else if tier == 3 {
					// Performance Outlier: Add to queue with Medium Energy
					queueMutex.Lock()
					seedQueue = append(seedQueue, &SeedEntry{
						Data: res.Mutated, Energy: StableEnergy, Tier: 3, Sig: sig,
					})
					queueMutex.Unlock()
					fmt.Printf("  [*] Found Performance Outlier: %s (Energy: %d)\n", sig[:8], StableEnergy)
				}
			}

			if currentCount > 0 && currentCount%1000 == 0 {
				cullQueue(&seedQueue)
				queueMutex.Lock()
                qLen := len(seedQueue)
                queueMutex.Unlock()
                
                fmt.Printf("  [%d/%d] Queue: %d | %s\n", currentCount, *maxIterations, qLen, mm.GetStatsSummary())
			}
		}
		resultsDone <- true
	}()

	var tasksSubmitted int64 = 0
	for atomic.LoadInt64(&tasksSubmitted) < int64(*maxIterations) {
		if ctx.Err() != nil { break }

		for len(tasks) < cap(tasks) && atomic.LoadInt64(&tasksSubmitted) < int64(*maxIterations) {
			queueMutex.Lock()
			if len(seedQueue) == 0 {
				queueMutex.Unlock()
				break
			}
			totalEnergy := 0
			for _, s := range seedQueue {
				totalEnergy += s.Energy
			}
			r := dispatcherRand.Intn(totalEnergy)
			var seed *SeedEntry
			curr := 0
			for _, s := range seedQueue {
				curr += s.Energy
				if r < curr {
					seed = s
					break
				}
			}
			seed.Picks++
			decay := 0.95
			if seed.Tier > 0 { decay = 0.99 }
			seed.Energy = int(float64(seed.Energy) * decay)
			if seed.Energy < LowEnergy { seed.Energy = LowEnergy }
			queueMutex.Unlock()

			tasks <- FuzzTask{Seed: seed}
			atomic.AddInt64(&tasksSubmitted, 1)
		}
		time.Sleep(10 * time.Millisecond)
	}

	close(tasks)
	wg.Wait()
	close(results)
	<-resultsDone

	cancel()

	consolidateLogs()

	campaignEndTime := time.Now()
	campaignEndISO := campaignEndTime.Format(time.RFC3339)
	campaignTotalSec := campaignEndTime.Sub(campaignStartTime).Seconds()

	os.MkdirAll("logs", 0755)
	summaryPath := filepath.Join("logs", "campaign_summary.csv")

	fileExists := false
	if _, err := os.Stat(summaryPath); err == nil {
		fileExists = true
	}

	f, err := os.OpenFile(summaryPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err == nil {
		defer f.Close()

		writer := csv.NewWriter(f)

		if !fileExists {
			writer.Write([]string{
				"target",
				"start_time",
				"end_time",
				"duration_sec",
				"iterations",
				"throughput_exec_per_sec",
				"worker_count",
				"timeout_sec",
				"max_iterations",
				"seed",
				"input_type",
			})
		}

		completed := atomic.LoadInt64(&count)
		throughput := 0.0
		if campaignTotalSec > 0 {
			throughput = float64(completed) / campaignTotalSec
		}

		writer.Write([]string{
			config.Target,
			campaignStartISO,
			campaignEndISO,
			fmt.Sprintf("%.6f", campaignTotalSec),
			strconv.FormatInt(completed, 10),
			fmt.Sprintf("%.6f", throughput),
			strconv.Itoa(*numWorkers),
			fmt.Sprintf("%.6f", config.Timeout),
			strconv.Itoa(*maxIterations),
			strconv.FormatInt(*seed, 10),
			config.Type,
		})

		writer.Flush()
		if err := writer.Error(); err != nil {
			fmt.Printf("Error writing campaign summary: %v\n", err)
		}
	} else {
		fmt.Printf("Error opening campaign summary file: %v\n", err)
	}
	fmt.Println("[*] Fuzzing complete")
}

func min(a, b int) int { if a < b { return a }; return b }
func max(a, b int) int { if a > b { return a }; return b }
