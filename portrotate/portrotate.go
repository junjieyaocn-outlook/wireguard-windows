/* SPDX-License-Identifier: MIT
 *
 * Package portrotate implements the client-side half of the daily port
 * rotation scheme: the server rotates its listening port every day at 04:00
 * local time to 40000 + month*100 + day (e.g. 2026-11-03 -> 41103,
 * 2027-01-03 -> 40103). Tunnels whose names start with "wg_" follow the
 * rotation by rewriting every peer's Endpoint port to the day's value.
 *
 * This package intentionally depends only on the Go standard library so it
 * can be unit tested on any platform.
 */

package portrotate

import (
	"strings"
	"time"
)

const (
	// NamePrefix limits rotation to tunnels participating in the scheme.
	NamePrefix = "wg_"
	// RotationHour and RotationMinute are the local time of the daily rotation.
	RotationHour   = 4
	RotationMinute = 0
)

// RotationPort returns the server port scheduled for the given date:
// 40000 + month*100 + day, e.g. 2026-11-03 -> 41103. The result always fits
// in the valid TCP/UDP port range (40101-41231).
func RotationPort(t time.Time) uint16 {
	return uint16(40000 + int(t.Month())*100 + t.Day())
}

// UntilNextRotation returns the duration until the next daily rotation
// moment: today at RotationHour:RotationMinute local time, or tomorrow at
// that time if today's moment has already passed.
func UntilNextRotation(now time.Time) time.Duration {
	next := time.Date(now.Year(), now.Month(), now.Day(), RotationHour, RotationMinute, 0, 0, now.Location())
	if !next.After(now) {
		next = next.Add(24 * time.Hour)
	}
	return next.Sub(now)
}

// TunnelEnabled reports whether the named tunnel participates in rotation.
func TunnelEnabled(name string) bool {
	return strings.HasPrefix(name, NamePrefix)
}
