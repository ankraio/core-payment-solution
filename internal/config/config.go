package config

import (
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type Duration time.Duration

func (duration Duration) Std() time.Duration { return time.Duration(duration) }

func (duration *Duration) UnmarshalYAML(value *yaml.Node) error {
	var asString string
	if stringError := value.Decode(&asString); stringError == nil && asString != "" {
		parsed, parseError := time.ParseDuration(asString)
		if parseError != nil {
			return parseError
		}
		*duration = Duration(parsed)
		return nil
	}
	var asSeconds int64
	if intError := value.Decode(&asSeconds); intError != nil {
		return intError
	}
	*duration = Duration(time.Duration(asSeconds) * time.Second)
	return nil
}

type Config struct {
	Collector  CollectorConfig  `yaml:"collector"`
	Detection  DetectionConfig  `yaml:"detection"`
	Alarm      AlarmConfig      `yaml:"alarm"`
	Slack      SlackConfig      `yaml:"slack"`
	Deception  DeceptionConfig  `yaml:"deception"`
	Services   []ServiceBanner  `yaml:"services"`
}

type CollectorConfig struct {
	IngestAddress    string `yaml:"ingest_address"`
	DashboardAddress string `yaml:"dashboard_address"`
	DataDirectory    string `yaml:"data_directory"`
}

type DetectionConfig struct {
	PortScanWindow         Duration `yaml:"port_scan_window"`
	PortScanDistinctPorts  int      `yaml:"port_scan_distinct_ports"`
	BruteForceWindow       Duration `yaml:"brute_force_window"`
	BruteForceAttempts     int      `yaml:"brute_force_attempts"`
	LateralMovementMinimum int      `yaml:"lateral_movement_distinct_machines"`
	SessionIdleTimeout     Duration `yaml:"session_idle_timeout"`
}

type AlarmConfig struct {
	MinimumSeverity  string   `yaml:"minimum_severity"`
	DebounceInterval Duration `yaml:"debounce_interval"`
	ReportAfterIdle  Duration `yaml:"report_after_idle"`
}

type SlackConfig struct {
	Enabled    bool   `yaml:"enabled"`
	WebhookEnv string `yaml:"webhook_env"`
	Channel    string `yaml:"channel"`
	Username   string `yaml:"username"`
}

type DeceptionConfig struct {
	OrganizationName string `yaml:"organization_name"`
	FakeCardCount    int    `yaml:"fake_card_count"`
	FakeAccountCount int    `yaml:"fake_account_count"`
}

type ServiceBanner struct {
	Name    string `yaml:"name"`
	Machine string `yaml:"machine"`
	Banner  string `yaml:"banner"`
	Version string `yaml:"version"`
}

func Default() Config {
	return Config{
		Collector: CollectorConfig{
			IngestAddress:    ":9400",
			DashboardAddress: "127.0.0.1:9500",
			DataDirectory:    "/var/lib/honeypot",
		},
		Detection: DetectionConfig{
			PortScanWindow:         Duration(30 * time.Second),
			PortScanDistinctPorts:  6,
			BruteForceWindow:       Duration(60 * time.Second),
			BruteForceAttempts:     5,
			LateralMovementMinimum: 2,
			SessionIdleTimeout:     Duration(10 * time.Minute),
		},
		Alarm: AlarmConfig{
			MinimumSeverity:  "medium",
			DebounceInterval: Duration(30 * time.Second),
			ReportAfterIdle:  Duration(5 * time.Minute),
		},
		Slack: SlackConfig{
			Enabled:    true,
			WebhookEnv: "SLACK_WEBHOOK_URL",
			Channel:    "#security-honeypot",
			Username:   "core-payments-sentinel",
		},
		Deception: DeceptionConfig{
			OrganizationName: "Core Payment Solution",
			FakeCardCount:    250,
			FakeAccountCount: 80,
		},
	}
}

func Load(path string) (Config, error) {
	configuration := Default()
	if path == "" {
		return configuration, nil
	}
	contents, readError := os.ReadFile(path)
	if readError != nil {
		if os.IsNotExist(readError) {
			return configuration, nil
		}
		return configuration, readError
	}
	if unmarshalError := yaml.Unmarshal(contents, &configuration); unmarshalError != nil {
		return configuration, unmarshalError
	}
	return configuration, nil
}
