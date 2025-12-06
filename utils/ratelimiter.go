package utils

import (
	"fmt"
	"io"
	"time"
)

// RateLimitedReader est un wrapper autour d'un io.Reader qui limite le débit de lecture
type RateLimitedReader struct {
	reader      io.Reader
	bytesPerSec int64         // Limite en bytes par seconde (0 = illimité)
	lastRead    time.Time     // Timestamp du dernier read
	accumulated int64         // Bytes accumulés dans la période courante
}

// NewRateLimitedReader crée un nouveau reader avec limitation de débit
// bytesPerSec: limite en bytes/sec (0 = illimité)
func NewRateLimitedReader(reader io.Reader, bytesPerSec int64) *RateLimitedReader {
	return &RateLimitedReader{
		reader:      reader,
		bytesPerSec: bytesPerSec,
		lastRead:    time.Now(),
		accumulated: 0,
	}
}

// Read implémente io.Reader avec limitation de débit
func (r *RateLimitedReader) Read(p []byte) (int, error) {
	// Si pas de limite, lire normalement
	if r.bytesPerSec <= 0 {
		return r.reader.Read(p)
	}

	// Lire les données
	n, err := r.reader.Read(p)
	if n <= 0 {
		return n, err
	}

	// Calculer le délai nécessaire pour respecter la limite
	r.accumulated += int64(n)
	now := time.Now()
	elapsed := now.Sub(r.lastRead)

	// Calculer combien de bytes on devrait avoir lu pendant elapsed
	allowedBytes := int64(elapsed.Seconds() * float64(r.bytesPerSec))

	// Si on a lu trop vite, attendre
	if r.accumulated > allowedBytes {
		// Calculer le délai nécessaire
		excessBytes := r.accumulated - allowedBytes
		sleepDuration := time.Duration(float64(excessBytes) / float64(r.bytesPerSec) * float64(time.Second))

		if sleepDuration > 0 {
			time.Sleep(sleepDuration)
		}
	}

	// Réinitialiser le compteur toutes les secondes pour éviter l'accumulation
	if elapsed >= time.Second {
		r.lastRead = now
		r.accumulated = 0
	}

	return n, err
}

// RateLimiter gère la limitation globale de bande passante pour plusieurs téléchargements
type RateLimiter struct {
	bytesPerSec   int64
	lastReset     time.Time
	bytesThisSec  int64
}

// NewRateLimiter crée un nouveau rate limiter global
func NewRateLimiter(bytesPerSec int64) *RateLimiter {
	return &RateLimiter{
		bytesPerSec:  bytesPerSec,
		lastReset:    time.Now(),
		bytesThisSec: 0,
	}
}

// Wait attend si nécessaire pour respecter la limite de bande passante
// Retourne immédiatement si pas de limite ou si la limite n'est pas atteinte
func (rl *RateLimiter) Wait(bytes int64) {
	if rl.bytesPerSec <= 0 {
		return // Pas de limite
	}

	now := time.Now()
	elapsed := now.Sub(rl.lastReset)

	// Réinitialiser le compteur chaque seconde
	if elapsed >= time.Second {
		rl.lastReset = now
		rl.bytesThisSec = 0
		elapsed = 0
	}

	rl.bytesThisSec += bytes

	// Si on a dépassé la limite, attendre
	if rl.bytesThisSec > rl.bytesPerSec {
		// Attendre jusqu'à la prochaine seconde
		sleepDuration := time.Second - elapsed
		if sleepDuration > 0 {
			time.Sleep(sleepDuration)
		}
		// Réinitialiser après l'attente
		rl.lastReset = time.Now()
		rl.bytesThisSec = 0
	}
}

// FormatBandwidth formate une vitesse en bytes/sec vers une chaîne lisible
func FormatBandwidth(bytesPerSec int64) string {
	if bytesPerSec <= 0 {
		return "unlimited"
	}

	const (
		KB = 1024
		MB = 1024 * KB
		GB = 1024 * MB
	)

	switch {
	case bytesPerSec >= GB:
		return fmt.Sprintf("%.2f GB/s", float64(bytesPerSec)/float64(GB))
	case bytesPerSec >= MB:
		return fmt.Sprintf("%.2f MB/s", float64(bytesPerSec)/float64(MB))
	case bytesPerSec >= KB:
		return fmt.Sprintf("%.2f KB/s", float64(bytesPerSec)/float64(KB))
	default:
		return fmt.Sprintf("%d B/s", bytesPerSec)
	}
}
