package transport

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/ankraio/core-payment-solution/internal/event"
	"github.com/ankraio/core-payment-solution/internal/log"
)

type Client struct {
	collectorURL string
	machine      string
	service      string
	spoolDir     string
	httpClient   *http.Client
	logger       *log.Logger
	queue        chan event.Event
	waitGroup    sync.WaitGroup
	closeOnce    sync.Once
	done         chan struct{}
}

type ClientOptions struct {
	CollectorURL string
	Machine      string
	Service      string
	SpoolDir     string
}

func NewClient(options ClientOptions) *Client {
	if options.CollectorURL == "" {
		options.CollectorURL = "http://collector:9400"
	}
	if options.SpoolDir == "" {
		options.SpoolDir = filepath.Join(os.TempDir(), "honeypot-spool", options.Service)
	}
	_ = os.MkdirAll(options.SpoolDir, 0o700)
	client := &Client{
		collectorURL: options.CollectorURL,
		machine:      options.Machine,
		service:      options.Service,
		spoolDir:     options.SpoolDir,
		httpClient:   &http.Client{Timeout: 5 * time.Second},
		logger:       log.New("transport." + options.Service),
		queue:        make(chan event.Event, 1024),
		done:         make(chan struct{}),
	}
	client.waitGroup.Add(1)
	go client.run()
	return client
}

func (client *Client) Emit(item event.Event) {
	if item.ID == "" {
		item.ID = newID()
	}
	if item.OccurredAt.IsZero() {
		item.OccurredAt = time.Now().UTC()
	}
	if item.Machine == "" {
		item.Machine = client.machine
	}
	if item.Service == "" {
		item.Service = client.service
	}
	select {
	case client.queue <- item:
	default:
		client.spool([]event.Event{item})
	}
}

func (client *Client) run() {
	defer client.waitGroup.Done()
	ticker := time.NewTicker(flushInterval())
	defer ticker.Stop()
	pending := make([]event.Event, 0, 64)
	flush := func() {
		if len(pending) == 0 {
			return
		}
		if sendError := client.send(pending); sendError != nil {
			client.spool(pending)
		}
		pending = pending[:0]
	}
	for {
		select {
		case <-client.done:
			drainLoop := true
			for drainLoop {
				select {
				case item := <-client.queue:
					pending = append(pending, item)
				default:
					drainLoop = false
				}
			}
			flush()
			return
		case item := <-client.queue:
			pending = append(pending, item)
			if len(pending) >= 32 {
				flush()
			}
		case <-ticker.C:
			flush()
			client.replaySpool()
		}
	}
}

func (client *Client) send(items []event.Event) error {
	body, marshalError := json.Marshal(event.Batch{Events: items})
	if marshalError != nil {
		return marshalError
	}
	request, requestError := http.NewRequestWithContext(context.Background(),
		http.MethodPost, client.collectorURL+"/ingest", bytes.NewReader(body))
	if requestError != nil {
		return requestError
	}
	request.Header.Set("Content-Type", "application/json")
	response, sendError := client.httpClient.Do(request)
	if sendError != nil {
		return sendError
	}
	defer response.Body.Close()
	if response.StatusCode >= 300 {
		return fmt.Errorf("collector returned status %d", response.StatusCode)
	}
	return nil
}

func (client *Client) spool(items []event.Event) {
	body, marshalError := json.Marshal(event.Batch{Events: items})
	if marshalError != nil {
		client.logger.Error("spool marshal failed", "error", marshalError)
		return
	}
	name := filepath.Join(client.spoolDir, fmt.Sprintf("%d-%s.json", time.Now().UnixNano(), newID()))
	if writeError := os.WriteFile(name, body, 0o600); writeError != nil {
		client.logger.Error("spool write failed", "error", writeError)
	}
}

func (client *Client) replaySpool() {
	entries, readError := os.ReadDir(client.spoolDir)
	if readError != nil {
		return
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		path := filepath.Join(client.spoolDir, entry.Name())
		contents, fileError := os.ReadFile(path)
		if fileError != nil {
			continue
		}
		var batch event.Batch
		if unmarshalError := json.Unmarshal(contents, &batch); unmarshalError != nil {
			_ = os.Remove(path)
			continue
		}
		if sendError := client.send(batch.Events); sendError != nil {
			return
		}
		_ = os.Remove(path)
	}
}

func (client *Client) Close() {
	client.closeOnce.Do(func() {
		close(client.done)
	})
	client.waitGroup.Wait()
}

func flushInterval() time.Duration {
	if raw := os.Getenv("TRANSPORT_FLUSH_INTERVAL"); raw != "" {
		if parsed, parseError := time.ParseDuration(raw); parseError == nil && parsed > 0 {
			return parsed
		}
	}
	return 2 * time.Second
}

func newID() string {
	buffer := make([]byte, 12)
	_, _ = rand.Read(buffer)
	return hex.EncodeToString(buffer)
}
