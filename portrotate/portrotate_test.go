/* SPDX-License-Identifier: MIT */

package portrotate

import (
	"testing"
	"time"
)

func TestRotationPort(t *testing.T) {
	cases := []struct {
		date string
		want uint16
	}{
		{"2026-11-03", 41103}, // 11月3日 -> 41103
		{"2027-01-03", 40103}, // 1月3日 -> 40103
		{"2026-12-31", 41231}, // 12月31日 -> 41231
		{"2026-02-09", 40209}, // 零填充检查
		{"2026-10-05", 41005},
	}
	for _, c := range cases {
		tm, err := time.Parse("2006-01-02", c.date)
		if err != nil {
			t.Fatal(err)
		}
		if got := RotationPort(tm); got != c.want {
			t.Errorf("RotationPort(%s) = %d, want %d", c.date, got, c.want)
		}
		if got := RotationPort(tm); got < 1024 || got > 65535 {
			t.Errorf("RotationPort(%s) = %d, out of valid port range", c.date, got)
		}
	}
}

func TestUntilNextRotation(t *testing.T) {
	loc := time.Local

	// 03:00 -> 下一次是今天 04:00，约 1 小时
	now := time.Date(2026, 10, 18, 3, 0, 0, 0, loc)
	if d := UntilNextRotation(now); d != time.Hour {
		t.Errorf("at 03:00: UntilNextRotation = %v, want 1h", d)
	}

	// 05:00 -> 下一次是明天 04:00，约 23 小时
	now = time.Date(2026, 10, 18, 5, 0, 0, 0, loc)
	if d := UntilNextRotation(now); d != 23*time.Hour {
		t.Errorf("at 05:00: UntilNextRotation = %v, want 23h", d)
	}

	// 04:00:30（刚过切换点）-> 下一次是明天 04:00
	now = time.Date(2026, 10, 18, 4, 0, 30, 0, loc)
	want := 24*time.Hour - 30*time.Second
	if d := UntilNextRotation(now); d != want {
		t.Errorf("at 04:00:30: UntilNextRotation = %v, want %v", d, want)
	}

	// 23:59:59 -> 下一次是明天 04:00，约 4 小时
	now = time.Date(2026, 10, 18, 23, 59, 59, 0, loc)
	want = 4*time.Hour + time.Second
	if d := UntilNextRotation(now); d != want {
		t.Errorf("at 23:59:59: UntilNextRotation = %v, want %v", d, want)
	}
}

func TestTunnelEnabled(t *testing.T) {
	enabled := []string{"wg_", "wg_home", "wg_2026", "wg_a_b_c"}
	for _, name := range enabled {
		if !TunnelEnabled(name) {
			t.Errorf("TunnelEnabled(%q) = false, want true", name)
		}
	}
	disabled := []string{"", "office", "WG_home", " wg_x", "xwg_"}
	for _, name := range disabled {
		if TunnelEnabled(name) {
			t.Errorf("TunnelEnabled(%q) = true, want false", name)
		}
	}
}
