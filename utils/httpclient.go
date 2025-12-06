package utils

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"
)

// HTTPClientConfig contient la configuration pour créer un client HTTP personnalisé
type HTTPClientConfig struct {
	NetworkInterface string // Interface réseau de sortie (ex: "eth0")
	ProxyEnabled     bool
	ProxyURL         string
	ProxyUsername    string
	ProxyPassword    string
	Timeout          time.Duration
}

// NewHTTPClient crée un client HTTP avec support de l'interface réseau et du proxy
func NewHTTPClient(config HTTPClientConfig) (*http.Client, error) {
	// Créer le transport de base
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: false,
		},
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
		DisableCompression:  false,
	}

	// Configurer le dialer avec l'interface réseau si spécifiée
	if config.NetworkInterface != "" {
		dialer, err := createInterfaceDialer(config.NetworkInterface)
		if err != nil {
			return nil, fmt.Errorf("failed to create interface dialer: %w", err)
		}
		transport.DialContext = dialer
	} else {
		// Dialer par défaut
		transport.DialContext = (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext
	}

	// Configurer le proxy si activé
	if config.ProxyEnabled && config.ProxyURL != "" {
		proxyURL, err := url.Parse(config.ProxyURL)
		if err != nil {
			return nil, fmt.Errorf("invalid proxy URL: %w", err)
		}

		// Ajouter l'authentification si fournie
		if config.ProxyUsername != "" {
			proxyURL.User = url.UserPassword(config.ProxyUsername, config.ProxyPassword)
		}

		transport.Proxy = http.ProxyURL(proxyURL)
	}

	// Timeout par défaut si non spécifié
	timeout := config.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}, nil
}

// createInterfaceDialer crée un dialer qui force l'utilisation d'une interface réseau spécifique
func createInterfaceDialer(interfaceName string) (func(ctx context.Context, network, addr string) (net.Conn, error), error) {
	// Récupérer l'interface réseau
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return nil, fmt.Errorf("interface %s not found: %w", interfaceName, err)
	}

	// Récupérer les adresses de l'interface
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, fmt.Errorf("failed to get addresses for interface %s: %w", interfaceName, err)
	}

	// Trouver une adresse IPv4
	var localAddr *net.TCPAddr
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok {
			if ipnet.IP.To4() != nil {
				localAddr = &net.TCPAddr{
					IP: ipnet.IP,
				}
				break
			}
		}
	}

	if localAddr == nil {
		return nil, fmt.Errorf("no IPv4 address found on interface %s", interfaceName)
	}

	// Créer le dialer avec l'adresse locale
	dialer := &net.Dialer{
		LocalAddr: localAddr,
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	return dialer.DialContext, nil
}

// GetInterfaceInfo retourne des informations sur une interface réseau
func GetInterfaceInfo(interfaceName string) (string, error) {
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return "", fmt.Errorf("interface not found: %w", err)
	}

	addrs, err := iface.Addrs()
	if err != nil {
		return "", fmt.Errorf("failed to get addresses: %w", err)
	}

	info := fmt.Sprintf("Interface: %s\n", iface.Name)
	info += fmt.Sprintf("Hardware Address: %s\n", iface.HardwareAddr.String())
	info += fmt.Sprintf("MTU: %d\n", iface.MTU)
	info += "Addresses:\n"

	for _, addr := range addrs {
		info += fmt.Sprintf("  - %s\n", addr.String())
	}

	return info, nil
}

// ListNetworkInterfaces retourne la liste de toutes les interfaces réseau disponibles
func ListNetworkInterfaces() ([]string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("failed to list interfaces: %w", err)
	}

	var result []string
	for _, iface := range interfaces {
		// Ne lister que les interfaces actives avec une adresse IP
		if iface.Flags&net.FlagUp != 0 {
			addrs, err := iface.Addrs()
			if err != nil {
				continue
			}
			if len(addrs) > 0 {
				result = append(result, iface.Name)
			}
		}
	}

	return result, nil
}
