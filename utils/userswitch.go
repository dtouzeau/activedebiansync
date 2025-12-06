package utils

import (
	"fmt"
	"os"
	"os/user"
	"strconv"
	"syscall"
)

// SwitchUser change l'utilisateur et le groupe du processus en cours
// Cette fonction doit être appelée avant de créer des fichiers ou d'ouvrir des sockets
func SwitchUser(username, groupname string) error {
	// Si aucun utilisateur n'est spécifié, ne rien faire
	if username == "" {
		return nil
	}

	// Vérifier si on a les privilèges root
	if os.Geteuid() != 0 {
		return fmt.Errorf("must be root to switch user (current euid: %d)", os.Geteuid())
	}

	// Récupérer l'utilisateur
	u, err := user.Lookup(username)
	if err != nil {
		return fmt.Errorf("failed to lookup user %s: %w", username, err)
	}

	// Convertir l'UID
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return fmt.Errorf("invalid UID for user %s: %w", username, err)
	}

	// Déterminer le GID
	var gid int
	if groupname != "" {
		// Groupe spécifique fourni
		g, err := user.LookupGroup(groupname)
		if err != nil {
			return fmt.Errorf("failed to lookup group %s: %w", groupname, err)
		}
		gid, err = strconv.Atoi(g.Gid)
		if err != nil {
			return fmt.Errorf("invalid GID for group %s: %w", groupname, err)
		}
	} else {
		// Utiliser le groupe primaire de l'utilisateur
		gid, err = strconv.Atoi(u.Gid)
		if err != nil {
			return fmt.Errorf("invalid GID for user %s: %w", username, err)
		}
	}

	// Récupérer les groupes supplémentaires de l'utilisateur
	groupIDs, err := u.GroupIds()
	if err != nil {
		return fmt.Errorf("failed to get supplementary groups for user %s: %w", username, err)
	}

	// Convertir les GIDs en int
	var gids []int
	for _, gidStr := range groupIDs {
		g, err := strconv.Atoi(gidStr)
		if err != nil {
			continue // Ignorer les GIDs invalides
		}
		gids = append(gids, g)
	}

	// Changer les groupes supplémentaires
	if err := syscall.Setgroups(gids); err != nil {
		return fmt.Errorf("failed to set supplementary groups: %w", err)
	}

	// Changer le GID
	if err := syscall.Setgid(gid); err != nil {
		return fmt.Errorf("failed to set GID %d: %w", gid, err)
	}

	// Changer l'UID (à faire en dernier car on perd les privilèges root après)
	if err := syscall.Setuid(uid); err != nil {
		return fmt.Errorf("failed to set UID %d: %w", uid, err)
	}

	return nil
}

// GetCurrentUser retourne l'utilisateur et le groupe actuels du processus
func GetCurrentUser() (string, string, error) {
	u, err := user.Current()
	if err != nil {
		return "", "", fmt.Errorf("failed to get current user: %w", err)
	}

	g, err := user.LookupGroupId(u.Gid)
	if err != nil {
		return u.Username, "", fmt.Errorf("failed to get current group: %w", err)
	}

	return u.Username, g.Name, nil
}

// ValidateUserGroup valide qu'un utilisateur et un groupe existent
func ValidateUserGroup(username, groupname string) error {
	if username == "" {
		return nil // Pas de validation si vide
	}

	// Vérifier l'utilisateur
	_, err := user.Lookup(username)
	if err != nil {
		return fmt.Errorf("user %s does not exist: %w", username, err)
	}

	// Vérifier le groupe si spécifié
	if groupname != "" {
		_, err := user.LookupGroup(groupname)
		if err != nil {
			return fmt.Errorf("group %s does not exist: %w", groupname, err)
		}
	}

	return nil
}
