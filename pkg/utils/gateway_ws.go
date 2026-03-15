package utils

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// GatewayWSClient manages a WebSocket connection to OpenClaw Gateway
type GatewayWSClient struct {
	conn    *websocket.Conn
	mu      sync.Mutex
	msgID   int
	timeout time.Duration
}

// WSMessage represents a Gateway WS protocol message
type WSMessage struct {
	ID     int             `json:"id,omitempty"`
	Method string          `json:"method,omitempty"`
	Params json.RawMessage `json:"params,omitempty"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *WSError        `json:"error,omitempty"`
}

type WSError struct {
	Code    int    `json:"code,omitempty"`
	Message string `json:"message,omitempty"`
}

// NewGatewayWSClient connects to the Gateway WS endpoint
func NewGatewayWSClient(target Target, token string, timeout time.Duration) (*GatewayWSClient, error) {
	return NewGatewayWSClientWithOrigin(target, token, timeout, "")
}

// NewGatewayWSClientWithOrigin connects with a custom Origin header for CSWSH testing
func NewGatewayWSClientWithOrigin(target Target, token string, timeout time.Duration, origin string) (*GatewayWSClient, error) {
	wsURL := target.WsURL()
	dialer := WsDialer(timeout)

	headers := http.Header{}
	if token != "" {
		headers.Set("Authorization", "Bearer "+token)
	}
	if origin != "" {
		headers.Set("Origin", origin)
	}

	conn, resp, err := dialer.Dial(wsURL, headers)
	if err != nil {
		if resp != nil {
			return nil, fmt.Errorf("ws connect failed (HTTP %d): %w", resp.StatusCode, err)
		}
		return nil, fmt.Errorf("ws connect failed: %w", err)
	}

	return &GatewayWSClient{
		conn:    conn,
		timeout: timeout,
	}, nil
}

// Call sends a JSON-RPC style method call and waits for response
func (c *GatewayWSClient) Call(method string, params interface{}) (json.RawMessage, error) {
	c.mu.Lock()
	c.msgID++
	id := c.msgID
	c.mu.Unlock()

	var paramsRaw json.RawMessage
	if params != nil {
		b, err := json.Marshal(params)
		if err != nil {
			return nil, fmt.Errorf("marshal params: %w", err)
		}
		paramsRaw = b
	}

	msg := WSMessage{
		ID:     id,
		Method: method,
		Params: paramsRaw,
	}

	c.conn.SetWriteDeadline(time.Now().Add(c.timeout))
	if err := c.conn.WriteJSON(msg); err != nil {
		return nil, fmt.Errorf("ws write: %w", err)
	}

	// Read responses until we get our ID back
	c.conn.SetReadDeadline(time.Now().Add(c.timeout))
	for {
		var resp WSMessage
		if err := c.conn.ReadJSON(&resp); err != nil {
			return nil, fmt.Errorf("ws read: %w", err)
		}
		if resp.ID == id {
			if resp.Error != nil {
				return nil, fmt.Errorf("rpc error %d: %s", resp.Error.Code, resp.Error.Message)
			}
			return resp.Result, nil
		}
		// Skip push messages / events with different IDs
	}
}

// CallRaw sends a raw JSON message and reads one response
func (c *GatewayWSClient) CallRaw(data []byte) ([]byte, error) {
	c.conn.SetWriteDeadline(time.Now().Add(c.timeout))
	if err := c.conn.WriteMessage(websocket.TextMessage, data); err != nil {
		return nil, err
	}
	c.conn.SetReadDeadline(time.Now().Add(c.timeout))
	_, msg, err := c.conn.ReadMessage()
	return msg, err
}

// Close closes the WebSocket connection
func (c *GatewayWSClient) Close() {
	if c.conn != nil {
		c.conn.Close()
	}
}
