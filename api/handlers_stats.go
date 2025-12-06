package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"
)

// handleTopPackages retourne les packages les plus téléchargés
func (api *RestAPI) handleTopPackages(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parser les paramètres
	nStr := r.URL.Query().Get("n")
	sinceStr := r.URL.Query().Get("since")

	n := 10 // Défaut
	if nStr != "" {
		if parsed, err := strconv.Atoi(nStr); err == nil && parsed > 0 {
			n = parsed
		}
	}

	// Parser "since" (format: 7d, 30d, 1h, etc.)
	since := time.Now().Add(-7 * 24 * time.Hour) // Défaut: 7 jours
	if sinceStr != "" {
		duration, err := parseDuration(sinceStr)
		if err == nil {
			since = time.Now().Add(-duration)
		}
	}

	// Obtenir les statistiques via le syncer
	analytics := api.syncer.GetAnalytics()
	if analytics == nil {
		http.Error(w, "Analytics not available", http.StatusInternalServerError)
		return
	}

	topPackages := analytics.GetTopPackages(n, since)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"top_packages": topPackages,
		"count":        len(topPackages),
		"since":        since,
		"requested":    n,
	})
}

// handleBandwidth retourne les statistiques de bande passante
func (api *RestAPI) handleBandwidth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	period := r.URL.Query().Get("period")
	if period == "" {
		period = "hour"
	}

	sinceStr := r.URL.Query().Get("since")
	since := time.Now().Add(-24 * time.Hour) // Défaut: 24h
	if sinceStr != "" {
		duration, err := parseDuration(sinceStr)
		if err == nil {
			since = time.Now().Add(-duration)
		}
	}

	analytics := api.syncer.GetAnalytics()
	if analytics == nil {
		http.Error(w, "Analytics not available", http.StatusInternalServerError)
		return
	}

	var bandwidth interface{}

	switch period {
	case "hour":
		bandwidth = analytics.GetBandwidthByHour(since)
	case "day":
		bandwidth = analytics.GetBandwidthByDay(since)
	default:
		http.Error(w, "Invalid period, use 'hour' or 'day'", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"period":    period,
		"since":     since,
		"bandwidth": bandwidth,
	})
}

// handleAnomalies retourne les anomalies détectées
func (api *RestAPI) handleAnomalies(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	analytics := api.syncer.GetAnalytics()
	if analytics == nil {
		http.Error(w, "Analytics not available", http.StatusInternalServerError)
		return
	}

	anomalies := analytics.DetectAnomalies()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"anomalies": anomalies,
		"count":     len(anomalies),
	})
}

// handleDiskPrediction retourne la prédiction d'utilisation disque
func (api *RestAPI) handleDiskPrediction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	daysStr := r.URL.Query().Get("days")
	days := 30 // Défaut: 30 jours
	if daysStr != "" {
		if parsed, err := strconv.Atoi(daysStr); err == nil && parsed > 0 {
			days = parsed
		}
	}

	analytics := api.syncer.GetAnalytics()
	if analytics == nil {
		http.Error(w, "Analytics not available", http.StatusInternalServerError)
		return
	}

	prediction, err := analytics.PredictDiskUsage(days)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to predict disk usage: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(prediction)
}

// parseDuration parse une durée au format "7d", "24h", "30m"
func parseDuration(s string) (time.Duration, error) {
	if len(s) < 2 {
		return 0, fmt.Errorf("invalid duration format")
	}

	value, err := strconv.Atoi(s[:len(s)-1])
	if err != nil {
		return 0, err
	}

	unit := s[len(s)-1:]
	switch unit {
	case "m":
		return time.Duration(value) * time.Minute, nil
	case "h":
		return time.Duration(value) * time.Hour, nil
	case "d":
		return time.Duration(value) * 24 * time.Hour, nil
	case "w":
		return time.Duration(value) * 7 * 24 * time.Hour, nil
	default:
		return 0, fmt.Errorf("invalid unit: %s", unit)
	}
}
