package websocket

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
)

const (
	// Time allowed to write a message to the peer
	writeWait = 10 * time.Second

	// Time allowed to read the next pong message from the peer
	pongWait = 60 * time.Second

	// Send pings to peer with this period (must be less than pongWait)
	pingPeriod = (pongWait * 9) / 10

	// Maximum message size allowed from peer
	maxMessageSize = 8192

	// Buffer size for send channel
	sendBufferSize = 256
)

// AllowedOrigins is the list of origins permitted to open WebSocket connections.
// It is injected from config at startup. If empty, same-origin requests are allowed.
var AllowedOrigins []string

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		origin := r.Header.Get("Origin")
		if origin == "" {
			// Non-browser clients (e.g., curl) have no Origin header
			return true
		}

		// If an allowlist is configured, enforce it.
		if len(AllowedOrigins) > 0 {
			for _, allowed := range AllowedOrigins {
				if origin == allowed {
					return true
				}
			}
			return false
		}

		// No allowlist configured: allow same-origin only.
		// Compare the Origin scheme+host against the request Host.
		originHost := extractHostFromOrigin(origin)
		return originHost == r.Host
	},
}

// extractHostFromOrigin strips the scheme from an Origin header value and
// returns the host:port component (e.g., "http://localhost:5173" → "localhost:5173").
func extractHostFromOrigin(origin string) string {
	if i := strings.Index(origin, "://"); i != -1 {
		return origin[i+3:]
	}
	return origin
}

// Client represents a WebSocket client
type Client struct {
	hub *Hub

	// Unique client ID
	ID string

	// User SID for directed messaging
	UserSID string

	// Username for logging
	Username string

	// The websocket connection
	conn *websocket.Conn

	// Buffered channel of outbound messages
	send chan []byte
}

// NewClient creates a new WebSocket client
func NewClient(hub *Hub, conn *websocket.Conn, userSID, username string) *Client {
	return &Client{
		hub:      hub,
		ID:       uuid.New().String(),
		UserSID:  userSID,
		Username: username,
		conn:     conn,
		send:     make(chan []byte, sendBufferSize),
	}
}

// readPump pumps messages from the websocket connection to the hub
func (c *Client) readPump() {
	defer func() {
		c.hub.Unregister(c)
		c.conn.Close()
	}()

	c.conn.SetReadLimit(maxMessageSize)
	c.conn.SetReadDeadline(time.Now().Add(pongWait))
	c.conn.SetPongHandler(func(string) error {
		c.conn.SetReadDeadline(time.Now().Add(pongWait))
		return nil
	})

	for {
		_, message, err := c.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("WebSocket error: %v", err)
			}
			break
		}

		// Handle incoming message
		c.handleMessage(message)
	}
}

// writePump pumps messages from the hub to the websocket connection
func (c *Client) writePump() {
	ticker := time.NewTicker(pingPeriod)
	defer func() {
		ticker.Stop()
		c.conn.Close()
	}()

	for {
		select {
		case message, ok := <-c.send:
			c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if !ok {
				// Hub closed the channel
				c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			w, err := c.conn.NextWriter(websocket.TextMessage)
			if err != nil {
				return
			}
			w.Write(message)

			// Add queued messages to the current websocket message
			n := len(c.send)
			for i := 0; i < n; i++ {
				w.Write([]byte{'\n'})
				w.Write(<-c.send)
			}

			if err := w.Close(); err != nil {
				return
			}

		case <-ticker.C:
			c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

// handleMessage processes incoming messages from the client
func (c *Client) handleMessage(message []byte) {
	var msg map[string]interface{}
	if err := json.Unmarshal(message, &msg); err != nil {
		log.Printf("Failed to parse WebSocket message: %v", err)
		return
	}

	msgType, _ := msg["type"].(string)

	switch msgType {
	case "PING":
		// Respond with pong
		c.sendJSON(map[string]interface{}{
			"type":      "PONG",
			"timestamp": time.Now(),
		})

	case "SUBSCRIBE":
		// Handle subscription requests
		topic, _ := msg["topic"].(string)
		log.Printf("Client %s subscribed to %s", c.ID, topic)

	case "UNSUBSCRIBE":
		// Handle unsubscription requests
		topic, _ := msg["topic"].(string)
		log.Printf("Client %s unsubscribed from %s", c.ID, topic)

	default:
		log.Printf("Unknown message type from client %s: %s", c.ID, msgType)
	}
}

// sendJSON sends a JSON message to the client
func (c *Client) sendJSON(v interface{}) {
	data, err := json.Marshal(v)
	if err != nil {
		log.Printf("Failed to marshal message: %v", err)
		return
	}

	select {
	case c.send <- data:
	default:
		// Buffer is full, drop message
		log.Printf("Send buffer full for client %s, dropping message", c.ID)
	}
}

// SendMessage sends a message to the client
func (c *Client) SendMessage(msg *Message) {
	data, err := json.Marshal(msg)
	if err != nil {
		return
	}

	select {
	case c.send <- data:
	default:
		// Buffer is full
	}
}

// Start starts the client read and write pumps
func (c *Client) Start() {
	// Start write pump first to ensure it's ready for reads
	go c.writePump()
	// Start read pump in current goroutine equivalent
	go c.readPump()
	log.Printf("WebSocket client %s started read/write pumps", c.ID)
}

// ServeWs handles websocket requests from the peer
func ServeWs(hub *Hub, w http.ResponseWriter, r *http.Request) {
	log.Printf("WebSocket upgrade request from %s", r.RemoteAddr)
	
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket upgrade error: %v", err)
		return
	}

	// Get user info from query params or headers
	userSID := r.URL.Query().Get("user_sid")
	username := r.URL.Query().Get("username")

	client := NewClient(hub, conn, userSID, username)
	hub.Register(client)

	log.Printf("WebSocket client created: %s (remote: %s)", client.ID, r.RemoteAddr)

	// Start client goroutines
	client.Start()
}
