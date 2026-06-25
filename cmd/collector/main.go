package main

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ankraio/core-payment-solution/internal/collector"
	"github.com/ankraio/core-payment-solution/internal/config"
	"github.com/ankraio/core-payment-solution/internal/log"
	"github.com/ankraio/core-payment-solution/internal/transport"
)

func main() {
	logger := log.New("collector.main")
	settings, loadError := config.Load(os.Getenv("HONEYPOT_CONFIG"))
	if loadError != nil {
		logger.Error("config load failed", "error", loadError)
		os.Exit(1)
	}
	if address := os.Getenv("INGEST_ADDRESS"); address != "" {
		settings.Collector.IngestAddress = address
	}
	if address := os.Getenv("DASHBOARD_ADDRESS"); address != "" {
		settings.Collector.DashboardAddress = address
	}
	if directory := os.Getenv("DATA_DIRECTORY"); directory != "" {
		settings.Collector.DataDirectory = directory
	}

	brain, newError := collector.New(settings)
	if newError != nil {
		logger.Error("collector init failed", "error", newError)
		os.Exit(1)
	}
	defer brain.Close()

	runContext, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	ingestServer := &http.Server{
		Addr:              settings.Collector.IngestAddress,
		Handler:           transport.IngestHandler{OnBatch: brain.Ingest},
		ReadHeaderTimeout: 5 * time.Second,
	}
	dashboardServer := &http.Server{
		Addr:              settings.Collector.DashboardAddress,
		Handler:           collector.NewDashboard(brain, os.Getenv("DASHBOARD_TOKEN")).Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		logger.Info("ingest listening", "address", settings.Collector.IngestAddress)
		if serveError := ingestServer.ListenAndServe(); serveError != nil && serveError != http.ErrServerClosed {
			logger.Error("ingest server failed", "error", serveError)
		}
	}()
	go func() {
		logger.Info("dashboard listening", "address", settings.Collector.DashboardAddress)
		if serveError := dashboardServer.ListenAndServe(); serveError != nil && serveError != http.ErrServerClosed {
			logger.Error("dashboard server failed", "error", serveError)
		}
	}()
	go brain.RunReportLoop(runContext)

	<-runContext.Done()
	logger.Info("shutting down")
	shutdownContext, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	_ = ingestServer.Shutdown(shutdownContext)
	_ = dashboardServer.Shutdown(shutdownContext)
}
