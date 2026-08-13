package websocket

import (
	"encoding/json"
	"log"
	"sync"
	"time"
)

// Message types
const (
	MessageTypeIncident        = "INCIDENT"
	MessageTypeApprovalRequest = "APPROVAL_REQUEST"
	MessageTypeApprovalDecision = "APPROVAL_DECISION"
	MessageTypeSystemAlert     = "SYSTEM_ALERT"
	MessageTypePolicyChange    = "POLICY_CHANGE"
	MessageTypeDeviceStatus    = "DEVICE_STATUS"
	MessageTypeFileEvent       = "FILE_EVENT"        // Real-time file activity events
	MessageTypeHeartbeat       = "HEARTBEAT"         // Device heartbeat notifications
)

// Message represents a WebSocket message
type Message struct {
	Type      string      `json:"type"`
	Payload   interface{} `json:"payload"`
	Timestamp time.Time   `json:"timestamp"`
	Target    string      `json:"target,omitempty"` // Optional: target user SID for directed messages
}

// Hub maintains the set of active clients and broadcasts messages to them
type Hub struct {
	// Registered clients
	clients map[*Client]bool

	// Clients mapped by user SID for directed messaging
	userClients map[string]map[*Client]bool

	// Inbound messages from clients
	broadcast chan *Message

	// Register requests from clients
	register chan *Client

	// Unregister requests from clients
	unregister chan *Client

	// Mutex for thread safety
	mu sync.RWMutex
}

// NewHub creates a new Hub instance
func NewHub() *Hub {
	return &Hub{
		clients:     make(map[*Client]bool),
		userClients: make(map[string]map[*Client]bool),
		broadcast:   make(chan *Message, 256),
		register:    make(chan *Client),
		unregister:  make(chan *Client),
	}
}

// Run starts the hub
func (h *Hub) Run() {
	for {
		select {
		case client := <-h.register:
			h.registerClient(client)

		case client := <-h.unregister:
			h.unregisterClient(client)

		case message := <-h.broadcast:
			h.broadcastMessage(message)
		}
	}
}

// registerClient adds a client to the hub
func (h *Hub) registerClient(client *Client) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.clients[client] = true

	// Register by user SID if available
	if client.UserSID != "" {
		if _, ok := h.userClients[client.UserSID]; !ok {
			h.userClients[client.UserSID] = make(map[*Client]bool)
		}
		h.userClients[client.UserSID][client] = true
	}

	log.Printf("WebSocket client registered: %s (user: %s)", client.ID, client.UserSID)
}

// unregisterClient removes a client from the hub
func (h *Hub) unregisterClient(client *Client) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if _, ok := h.clients[client]; ok {
		delete(h.clients, client)
		close(client.send)

		// Remove from user clients
		if client.UserSID != "" {
			if userClients, ok := h.userClients[client.UserSID]; ok {
				delete(userClients, client)
				if len(userClients) == 0 {
					delete(h.userClients, client.UserSID)
				}
			}
		}

		log.Printf("WebSocket client unregistered: %s", client.ID)
	}
}

// broadcastMessage sends a message to all clients or specific users
func (h *Hub) broadcastMessage(message *Message) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	data, err := json.Marshal(message)
	if err != nil {
		log.Printf("Failed to marshal WebSocket message: %v", err)
		return
	}

	// If target is specified, send only to that user
	if message.Target != "" {
		if userClients, ok := h.userClients[message.Target]; ok {
			for client := range userClients {
				select {
				case client.send <- data:
				default:
					// Client buffer is full, skip
				}
			}
		}
		return
	}

	// Broadcast to all clients
	for client := range h.clients {
		select {
		case client.send <- data:
		default:
			// Client buffer is full, skip
		}
	}
}

// Broadcast sends a message to all connected clients
func (h *Hub) Broadcast(msgType string, payload interface{}) {
	msg := &Message{
		Type:      msgType,
		Payload:   payload,
		Timestamp: time.Now(),
	}
	h.broadcast <- msg
}

// BroadcastToUser sends a message to a specific user
func (h *Hub) BroadcastToUser(userSID, msgType string, payload interface{}) {
	msg := &Message{
		Type:      msgType,
		Payload:   payload,
		Timestamp: time.Now(),
		Target:    userSID,
	}
	h.broadcast <- msg
}

// BroadcastIncident broadcasts an incident to all clients
func (h *Hub) BroadcastIncident(incident interface{}) {
	h.Broadcast(MessageTypeIncident, incident)
}

// BroadcastApprovalRequest sends an approval request to the owner
func (h *Hub) BroadcastApprovalRequest(ownerSID string, request interface{}) {
	h.BroadcastToUser(ownerSID, MessageTypeApprovalRequest, request)
}

// BroadcastApprovalDecision sends an approval decision to the requester
func (h *Hub) BroadcastApprovalDecision(requesterSID string, decision interface{}) {
	h.BroadcastToUser(requesterSID, MessageTypeApprovalDecision, decision)
}

// BroadcastSystemAlert sends a system alert to all clients
func (h *Hub) BroadcastSystemAlert(alert interface{}) {
	h.Broadcast(MessageTypeSystemAlert, alert)
}

// BroadcastPolicyChange notifies all clients of a policy change
func (h *Hub) BroadcastPolicyChange(change interface{}) {
	h.Broadcast(MessageTypePolicyChange, change)
}

// BroadcastDeviceStatus broadcasts device status changes
func (h *Hub) BroadcastDeviceStatus(status interface{}) {
	h.Broadcast(MessageTypeDeviceStatus, status)
}

// BroadcastFileEvent broadcasts file events to all connected clients
func (h *Hub) BroadcastFileEvent(event interface{}) {
	clientCount := h.GetClientCount()
	log.Printf("[WebSocket] Broadcasting FILE_EVENT to %d clients", clientCount)
	h.Broadcast(MessageTypeFileEvent, event)
}

// GetClientCount returns the number of connected clients
func (h *Hub) GetClientCount() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.clients)
}

// GetUserClientCount returns the number of connected clients for a user
func (h *Hub) GetUserClientCount(userSID string) int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	if userClients, ok := h.userClients[userSID]; ok {
		return len(userClients)
	}
	return 0
}

// IsUserOnline checks if a user has any connected clients
func (h *Hub) IsUserOnline(userSID string) bool {
	return h.GetUserClientCount(userSID) > 0
}

// GetOnlineUsers returns a list of online user SIDs
func (h *Hub) GetOnlineUsers() []string {
	h.mu.RLock()
	defer h.mu.RUnlock()

	users := make([]string, 0, len(h.userClients))
	for userSID := range h.userClients {
		users = append(users, userSID)
	}
	return users
}

// Register adds a client to the hub
func (h *Hub) Register(client *Client) {
	h.register <- client
}

// Unregister removes a client from the hub
func (h *Hub) Unregister(client *Client) {
	h.unregister <- client
}
