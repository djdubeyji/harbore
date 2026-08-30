package websocket

import (
	"encoding/json"
	"log"
	"net/http"
	"sync"

	"github.com/gorilla/websocket"
	"harbore.dev/orchestrator/models"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 4096,
	CheckOrigin: func(r *http.Request) bool {
		return true // Handle CORS separately
	},
}

type Client struct {
	scanID string
	conn   *websocket.Conn
	send   chan []byte
}

type Hub struct {
	mu      sync.RWMutex
	clients map[string]map[*Client]bool // scanID → clients
}

func NewHub() *Hub {
	return &Hub{
		clients: make(map[string]map[*Client]bool),
	}
}

// Upgrade upgrades an HTTP connection to WebSocket and registers the client.
func (h *Hub) Upgrade(w http.ResponseWriter, r *http.Request, scanID string) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("[ws] upgrade error: %v", err)
		return
	}

	client := &Client{
		scanID: scanID,
		conn:   conn,
		send:   make(chan []byte, 256),
	}

	h.register(client)
	go client.writePump(h)
	go client.readPump(h)
}

// Broadcast sends an event to all clients subscribed to a scan.
func (h *Hub) Broadcast(scanID string, event *models.WSEvent) {
	data, err := json.Marshal(event)
	if err != nil {
		log.Printf("[ws] marshal event error: %v", err)
		return
	}

	h.mu.RLock()
	clients := h.clients[scanID]
	h.mu.RUnlock()

	for client := range clients {
		select {
		case client.send <- data:
		default:
			h.unregister(client)
		}
	}
}

// BroadcastAll broadcasts to all connected clients (e.g. system events).
func (h *Hub) BroadcastAll(event *models.WSEvent) {
	data, err := json.Marshal(event)
	if err != nil {
		return
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	for _, clients := range h.clients {
		for client := range clients {
			select {
			case client.send <- data:
			default:
				go h.unregister(client)
			}
		}
	}
}

func (h *Hub) register(c *Client) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.clients[c.scanID] == nil {
		h.clients[c.scanID] = make(map[*Client]bool)
	}
	h.clients[c.scanID][c] = true
	log.Printf("[ws] client connected scan=%s total=%d", c.scanID[:8], len(h.clients[c.scanID]))
}

func (h *Hub) unregister(c *Client) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, ok := h.clients[c.scanID]; ok {
		delete(h.clients[c.scanID], c)
		if len(h.clients[c.scanID]) == 0 {
			delete(h.clients, c.scanID)
		}
		close(c.send)
	}
	c.conn.Close()
}

// writePump pumps messages from the hub to the WebSocket connection.
func (c *Client) writePump(h *Hub) {
	defer h.unregister(c)
	for msg := range c.send {
		if err := c.conn.WriteMessage(websocket.TextMessage, msg); err != nil {
			return
		}
	}
}

// readPump reads from the client (mainly for ping/pong and close).
func (c *Client) readPump(h *Hub) {
	defer h.unregister(c)
	c.conn.SetReadLimit(512)
	for {
		_, _, err := c.conn.ReadMessage()
		if err != nil {
			return
		}
	}
}
