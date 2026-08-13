package approval

import (
	"encoding/json"
	"fmt"
	"sync"
)

// NotificationMessage represents a notification to send
type NotificationMessage struct {
	Type      string      `json:"type"`
	RequestID string      `json:"request_id"`
	Recipient string      `json:"recipient"` // SID of recipient
	Title     string      `json:"title"`
	Message   string      `json:"message"`
	Data      interface{} `json:"data"`
	Priority  string      `json:"priority"` // LOW, NORMAL, HIGH, URGENT
}

// NotificationHandler is a function that handles notifications
type NotificationHandler func(msg *NotificationMessage)

// Notifier handles real-time notifications for approvals
type Notifier struct {
	mu       sync.RWMutex
	handlers []NotificationHandler
}

// NewNotifier creates a new approval notifier
func NewNotifier() *Notifier {
	return &Notifier{
		handlers: make([]NotificationHandler, 0),
	}
}

// AddHandler adds a notification handler
func (n *Notifier) AddHandler(handler NotificationHandler) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.handlers = append(n.handlers, handler)
}

// RemoveAllHandlers removes all notification handlers
func (n *Notifier) RemoveAllHandlers() {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.handlers = make([]NotificationHandler, 0)
}

// NotifyApprovalRequest notifies the owner of a new approval request
func (n *Notifier) NotifyApprovalRequest(req *ApprovalRequest) {
	msg := &NotificationMessage{
		Type:      "APPROVAL_REQUEST",
		RequestID: req.RequestID,
		Recipient: req.OwnerSID,
		Title:     "New Approval Request",
		Message:   fmt.Sprintf("%s wants to %s file: %s", req.RequesterUsername, formatAction(req.ActionType), req.FileName),
		Priority:  "HIGH",
		Data: map[string]interface{}{
			"request_id":     req.RequestID,
			"requester":      req.RequesterUsername,
			"file_name":      req.FileName,
			"file_hash":      req.FileHash,
			"action":         req.ActionType,
			"destination":    req.DestinationDetail,
			"classification": req.FileClassification,
			"expires_at":     req.TimeoutAt,
		},
	}

	n.send(msg)
}

// NotifyApprovalDecision notifies the requester of an approval decision
func (n *Notifier) NotifyApprovalDecision(req *ApprovalRequest) {
	var title, message string
	var priority string

	switch req.Status {
	case "APPROVED":
		title = "Request Approved"
		message = fmt.Sprintf("Your request to %s %s has been approved by %s", formatAction(req.ActionType), req.FileName, req.OwnerUsername)
		priority = "NORMAL"
	case "DENIED":
		title = "Request Denied"
		message = fmt.Sprintf("Your request to %s %s has been denied by %s", formatAction(req.ActionType), req.FileName, req.OwnerUsername)
		priority = "HIGH"
	case "TIMEOUT":
		title = "Request Expired"
		message = fmt.Sprintf("Your request to %s %s has expired", formatAction(req.ActionType), req.FileName)
		priority = "NORMAL"
	default:
		return
	}

	msg := &NotificationMessage{
		Type:      "APPROVAL_DECISION",
		RequestID: req.RequestID,
		Recipient: req.RequesterSID,
		Title:     title,
		Message:   message,
		Priority:  priority,
		Data: map[string]interface{}{
			"request_id": req.RequestID,
			"file_name":  req.FileName,
			"action":     req.ActionType,
			"decision":   req.Status,
			"comment":    req.DecisionComment,
			"owner":      req.OwnerUsername,
			"decided_at": req.DecidedAt,
		},
	}

	n.send(msg)
}

// NotifyReminder sends a reminder to the owner about pending request
func (n *Notifier) NotifyReminder(req *ApprovalRequest) {
	msg := &NotificationMessage{
		Type:      "APPROVAL_REMINDER",
		RequestID: req.RequestID,
		Recipient: req.OwnerSID,
		Title:     "Pending Approval Reminder",
		Message:   fmt.Sprintf("Reminder: %s is waiting for your approval to %s %s", req.RequesterUsername, formatAction(req.ActionType), req.FileName),
		Priority:  "URGENT",
		Data: map[string]interface{}{
			"request_id":        req.RequestID,
			"requester":         req.RequesterUsername,
			"file_name":         req.FileName,
			"action":            req.ActionType,
			"seconds_remaining": req.SecondsRemaining,
		},
	}

	n.send(msg)
}

// send sends a notification to all handlers
func (n *Notifier) send(msg *NotificationMessage) {
	n.mu.RLock()
	defer n.mu.RUnlock()

	for _, handler := range n.handlers {
		go handler(msg)
	}
}

// ToJSON converts a notification message to JSON
func (msg *NotificationMessage) ToJSON() ([]byte, error) {
	return json.Marshal(msg)
}

// formatAction formats an action type for display
func formatAction(action string) string {
	switch action {
	case "UPLOAD":
		return "upload"
	case "USB_TRANSFER":
		return "transfer to USB"
	case "EMAIL_ATTACH":
		return "attach to email"
	case "PRINT":
		return "print"
	case "COPY":
		return "copy"
	case "CLOUD_SYNC":
		return "sync to cloud"
	case "NETWORK_SHARE":
		return "share on network"
	default:
		return action
	}
}
