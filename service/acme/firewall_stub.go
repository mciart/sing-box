//go:build !linux || !with_acme

package acme

import "errors"

func syncACMEFirewall(allows []firewallAllow) (bool, error) {
	if len(allows) == 0 {
		return false, nil
	}
	return false, errors.New("open_firewall is only supported on linux")
}

func closeACMEFirewall() error {
	return nil
}
