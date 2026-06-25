package slack

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/ankraio/core-payment-solution/internal/alarm"
	"github.com/ankraio/core-payment-solution/internal/audit"
	"github.com/ankraio/core-payment-solution/internal/config"
	"github.com/ankraio/core-payment-solution/internal/log"
)

type Notifier struct {
	webhookURL string
	channel    string
	username   string
	enabled    bool
	httpClient *http.Client
	logger     *log.Logger
}

func NewNotifier(settings config.SlackConfig) *Notifier {
	webhookURL := os.Getenv(settings.WebhookEnv)
	notifier := &Notifier{
		webhookURL: webhookURL,
		channel:    settings.Channel,
		username:   settings.Username,
		enabled:    settings.Enabled && webhookURL != "",
		httpClient: &http.Client{Timeout: 8 * time.Second},
		logger:     log.New("slack"),
	}
	if settings.Enabled && webhookURL == "" {
		notifier.logger.Warn("slack enabled but webhook env empty; notifications will be logged only")
	}
	return notifier
}

type message struct {
	Channel  string `json:"channel,omitempty"`
	Username string `json:"username,omitempty"`
	Text     string `json:"text"`
}

func (notifier *Notifier) NotifyAlarm(runContext context.Context, raised alarm.Alarm) {
	text := fmt.Sprintf(":rotating_light: *%s* [%s]\n> %s\n*Source:* `%s`  *Session:* `%s`  *Signature:* `%s`",
		raised.Title, raised.Severity, raised.Detail, raised.SourceIP, raised.SessionID, raised.Signature)
	notifier.post(runContext, text)
}

func (notifier *Notifier) NotifyReport(runContext context.Context, report audit.Report) {
	text := fmt.Sprintf(":mag: *Intrusion report* `%s`\n*Source:* `%s`  *Duration:* %s  *Max severity:* *%s*\n*Machines:* %v\n*Route:* %s",
		report.SessionID, report.SourceIP, report.DurationLabel, report.MaxSeverity,
		report.Machines, routeSummary(report))
	notifier.post(runContext, text)
}

func routeSummary(report audit.Report) string {
	if len(report.Route) == 0 {
		return "(no route)"
	}
	parts := make([]string, 0, len(report.Route))
	for _, hop := range report.Route {
		label := hop.Machine
		if label == "" {
			label = hop.Service
		}
		parts = append(parts, label)
	}
	summary := parts[0]
	for index := 1; index < len(parts); index++ {
		summary += " -> " + parts[index]
	}
	return summary
}

func (notifier *Notifier) post(runContext context.Context, text string) {
	if !notifier.enabled {
		notifier.logger.Info("slack notification (disabled, logging only)", "text", text)
		return
	}
	body, marshalError := json.Marshal(message{Channel: notifier.channel, Username: notifier.username, Text: text})
	if marshalError != nil {
		notifier.logger.Error("slack marshal failed", "error", marshalError)
		return
	}
	request, requestError := http.NewRequestWithContext(runContext, http.MethodPost, notifier.webhookURL, bytes.NewReader(body))
	if requestError != nil {
		notifier.logger.Error("slack request build failed", "error", requestError)
		return
	}
	request.Header.Set("Content-Type", "application/json")
	response, sendError := notifier.httpClient.Do(request)
	if sendError != nil {
		notifier.logger.Error("slack post failed", "error", sendError)
		return
	}
	defer response.Body.Close()
	if response.StatusCode >= 300 {
		notifier.logger.Error("slack post returned error", "status", response.StatusCode)
	}
}
