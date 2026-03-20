package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type Client struct {
	BaseURL    string
	httpClient *http.Client
}

func NewClient(baseURL string) *Client {
	return &Client{
		BaseURL: baseURL,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// --- Request/Response types ---

type CompileRequest struct {
	Source   string `json:"source"`
	Language string `json:"language"`
}

type CompileResult struct {
	Instructions []Instruction `json:"instructions"`
	InsnCount    int           `json:"insn_count"`
	IR           string        `json:"ir"`
	MapSpecs     []MapSpec     `json:"map_specs"`
	Error        string        `json:"error"`
	ErrorDetail  interface{}   `json:"error_detail"`
}

type InitRequest struct {
	Source    string `json:"source"`
	PacketHex string `json:"packet_hex"`
	Language  string `json:"language"`
}

type InitResult struct {
	SessionID    string            `json:"session_id"`
	Instructions []Instruction     `json:"instructions"`
	IR           string            `json:"ir"`
	State        VMState           `json:"state"`
	SourceMap    map[string][2]int `json:"source_map"`
	MapSpecs     []MapSpec         `json:"map_specs"`
}

type StepRequest struct {
	SessionID string `json:"session_id"`
}

type RunRequest struct {
	SessionID string `json:"session_id"`
}

type ResetRequest struct {
	SessionID string `json:"session_id"`
	PacketHex string `json:"packet_hex"`
}

type RunToBreakpointRequest struct {
	SessionID   string `json:"session_id"`
	Breakpoints []int  `json:"breakpoints"`
}

type StepResult struct {
	State VMState `json:"state"`
}

type VMState struct {
	PC           int         `json:"pc"`
	InsnExecuted int         `json:"insn_executed"`
	InsnCount    int         `json:"insn_count"`
	Status       string      `json:"status"`
	Result       *int        `json:"result"`
	Registers    []Register  `json:"registers"`
	Stack        []StackSlot `json:"stack"`
	Maps         []MapState  `json:"maps"`
}

type Register struct {
	Index int    `json:"index"`
	Value string `json:"value"`
}

type StackSlot struct {
	Offset int    `json:"offset"`
	Value  string `json:"value"`
}

type MapSpec struct {
	FD        int    `json:"fd"`
	Type      string `json:"type"`
	KeySize   int    `json:"key_size"`
	ValueSize int    `json:"value_size"`
	MaxEntries int   `json:"max_entries"`
}

type MapState struct {
	FD        int        `json:"fd"`
	Type      string     `json:"type"`
	KeySize   int        `json:"key_size"`
	ValueSize int        `json:"value_size"`
	Entries   []MapEntry `json:"entries"`
}

type MapEntry struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type Instruction struct {
	PC   int    `json:"pc"`
	Text string `json:"text"`
}

type ExamplesResult struct {
	Examples []string `json:"examples"`
}

type ExampleResult struct {
	Source string `json:"source"`
}

// --- API methods ---

func (c *Client) postJSON(path string, body interface{}, result interface{}) error {
	data, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}

	resp, err := c.httpClient.Post(c.BaseURL+path, "application/json", bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		// Try to parse error from body
		var errResp struct {
			Error       string      `json:"error"`
			ErrorDetail interface{} `json:"error_detail"`
		}
		if json.Unmarshal(respBody, &errResp) == nil && errResp.Error != "" {
			return fmt.Errorf("%s", errResp.Error)
		}
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(respBody))
	}

	if err := json.Unmarshal(respBody, result); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}

func (c *Client) getJSON(path string, result interface{}) error {
	resp, err := c.httpClient.Get(c.BaseURL + path)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(respBody))
	}

	if err := json.Unmarshal(respBody, result); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}

func (c *Client) Compile(source, language string) (*CompileResult, error) {
	var result CompileResult
	err := c.postJSON("/api/compile", CompileRequest{
		Source:   source,
		Language: language,
	}, &result)
	if err != nil {
		return nil, err
	}
	if result.Error != "" {
		return &result, fmt.Errorf("%s", result.Error)
	}
	return &result, nil
}

func (c *Client) Init(source, packetHex, language string) (*InitResult, error) {
	var result InitResult
	err := c.postJSON("/api/init", InitRequest{
		Source:    source,
		PacketHex: packetHex,
		Language:  language,
	}, &result)
	return &result, err
}

func (c *Client) Step(sessionID string) (*VMState, error) {
	var result StepResult
	err := c.postJSON("/api/step", StepRequest{SessionID: sessionID}, &result)
	return &result.State, err
}

func (c *Client) Run(sessionID string) (*VMState, error) {
	var result StepResult
	err := c.postJSON("/api/run", RunRequest{SessionID: sessionID}, &result)
	return &result.State, err
}

func (c *Client) Reset(sessionID, packetHex string) (*VMState, error) {
	var result StepResult
	err := c.postJSON("/api/reset", ResetRequest{
		SessionID: sessionID,
		PacketHex: packetHex,
	}, &result)
	return &result.State, err
}

func (c *Client) RunToBreakpoint(sessionID string, breakpoints []int) (*VMState, error) {
	var result StepResult
	err := c.postJSON("/api/run_to_breakpoint", RunToBreakpointRequest{
		SessionID:   sessionID,
		Breakpoints: breakpoints,
	}, &result)
	return &result.State, err
}

func (c *Client) Examples() ([]string, error) {
	var result ExamplesResult
	err := c.getJSON("/api/examples", &result)
	return result.Examples, err
}

func (c *Client) LoadExample(name string) (string, error) {
	var result ExampleResult
	err := c.getJSON("/api/example/"+name, &result)
	return result.Source, err
}

// Ping checks if the backend is reachable.
func (c *Client) Ping() error {
	_, err := c.Examples()
	return err
}
