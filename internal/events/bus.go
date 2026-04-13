package events

import (
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"time"
)

const (
	NATSHost = "127.0.0.1"
	NATSPort = 4222
)

// NATSClient is a minimal raw NATS client
type NATSClient struct {
	conn     net.Conn
	mu       sync.Mutex
	buf      string
	handlers map[int]func(subject, payload string)
	nextSID  int
}

func NewNATSClient() (*NATSClient, error) {
	conn, err := net.DialTimeout(
		"tcp",
		fmt.Sprintf("%s:%d", NATSHost, NATSPort),
		5*time.Second,
	)
	if err != nil {
		return nil, fmt.Errorf("NATS connect failed: %w", err)
	}

	// Read INFO
	tmp := make([]byte, 1024)
	conn.Read(tmp)

	// Send CONNECT
	conn.Write([]byte(`CONNECT {"verbose":false}` + "\r\n"))

	return &NATSClient{
		conn:     conn,
		handlers: make(map[int]func(string, string)),
		nextSID:  1,
	}, nil
}

func (c *NATSClient) Publish(subject string, payload interface{}) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	msg := fmt.Sprintf("PUB %s %d\r\n%s\r\n", subject, len(data), data)
	c.mu.Lock()
	defer c.mu.Unlock()
	_, err = c.conn.Write([]byte(msg))
	return err
}

func (c *NATSClient) Subscribe(subject string, handler func(subject, payload string)) {
	sid := c.nextSID
	c.nextSID++
	c.handlers[sid] = handler
	c.conn.Write([]byte(fmt.Sprintf("SUB %s %d\r\n", subject, sid)))
}

func (c *NATSClient) Listen() {
	buf := make([]byte, 65536)
	pending := ""
	for {
		n, err := c.conn.Read(buf)
		if err != nil {
			return
		}
		pending += string(buf[:n])
		for {
			idx := -1
			for i := 0; i < len(pending)-1; i++ {
				if pending[i] == '\r' && pending[i+1] == '\n' {
					idx = i
					break
				}
			}
			if idx < 0 {
				break
			}
			line := pending[:idx]
			pending = pending[idx+2:]

			if len(line) > 4 && line[:4] == "MSG " {
				var subject string
				var sid, nbytes int
				fmt.Sscanf(line, "MSG %s %d %d", &subject, &sid, &nbytes)
				if len(pending) >= nbytes {
					payload := pending[:nbytes]
					pending = pending[nbytes:]
					if len(pending) >= 2 {
						pending = pending[2:]
					}
					if h, ok := c.handlers[sid]; ok {
						go h(subject, payload)
					}
				}
			}
		}
	}
}
