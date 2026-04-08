package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"strings"
	"time"
)

const codexBaseURL = "https://chatgpt.com"

// UsageResult holds parsed usage info for one credential.
type UsageResult struct {
	File          string
	AccountID     string
	Email         string
	PlanType      string
	Allowed       bool
	LimitReached  bool
	UpstreamStatus int

	FiveHour *WindowInfo
	Weekly   *WindowInfo

	RawJSON string
	Err     error
}

// WindowInfo mirrors the rate_limit window fields from the API response.
type WindowInfo struct {
	UsedPercent        float64
	ResetAt            int64
	ResetAfterSeconds  float64
	LimitWindowSeconds float64
}

// fetchUsage calls GET /backend-api/wham/usage and returns a UsageResult.
// If the token is expired (401/403) and a refresh_token is present, it refreshes automatically.
func fetchUsage(ctx context.Context, client *http.Client, entry keyEntry) UsageResult {
	res := UsageResult{
		File:      entry.path,
		AccountID: entry.key.AccountID,
		Email:     entry.key.Email,
	}

	statusCode, body, err := doFetchUsage(ctx, client, entry.key.AccessToken, entry.key.AccountID)
	if err != nil {
		res.Err = err
		return res
	}

	// Auto-refresh on 401/403
	if (statusCode == http.StatusUnauthorized || statusCode == http.StatusForbidden) &&
		strings.TrimSpace(entry.key.RefreshToken) != "" {
		infof("  token expired (HTTP %d), refreshing...", statusCode)
		refreshCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		renewedKey, refreshErr := renewKeyEntry(refreshCtx, client, entry, codexOAuthTokenURL)
		if refreshErr == nil {
			entry.key = renewedKey
			infof("  token refreshed and saved to %s", entry.path)
			statusCode, body, err = doFetchUsage(ctx, client, entry.key.AccessToken, entry.key.AccountID)
			if err != nil {
				res.Err = err
				return res
			}
		} else {
			warnf("  token refresh failed: %v", refreshErr)
		}
	}

	res.UpstreamStatus = statusCode
	res.RawJSON = string(body)

	var payload map[string]any
	if jsonErr := json.Unmarshal(body, &payload); jsonErr != nil {
		res.Err = fmt.Errorf("parse usage response: %w", jsonErr)
		return res
	}

	parseUsagePayload(&res, payload)
	return res
}

func doFetchUsage(ctx context.Context, client *http.Client, accessToken, accountID string) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		codexBaseURL+"/backend-api/wham/usage", nil)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(accessToken))
	req.Header.Set("chatgpt-account-id", strings.TrimSpace(accountID))
	req.Header.Set("Accept", "application/json")
	req.Header.Set("originator", "codex_cli_rs")

	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, nil, err
	}
	return resp.StatusCode, body, nil
}

// parseUsagePayload mirrors resolveRateLimitWindows from CodexUsageModal.jsx
func parseUsagePayload(res *UsageResult, payload map[string]any) {
	planType := ""
	if v, ok := payload["plan_type"].(string); ok {
		planType = strings.TrimSpace(strings.ToLower(v))
	}

	rateLimit, _ := payload["rate_limit"].(map[string]any)
	if rateLimit == nil {
		rateLimit = map[string]any{}
	}

	if planType == "" {
		if v, ok := rateLimit["plan_type"].(string); ok {
			planType = strings.TrimSpace(strings.ToLower(v))
		}
	}
	res.PlanType = planType

	if v, ok := rateLimit["allowed"].(bool); ok {
		res.Allowed = v
	}
	if v, ok := rateLimit["limit_reached"].(bool); ok {
		res.LimitReached = v
	}

	primary, _ := rateLimit["primary_window"].(map[string]any)
	secondary, _ := rateLimit["secondary_window"].(map[string]any)

	windows := []map[string]any{}
	if primary != nil {
		windows = append(windows, primary)
	}
	if secondary != nil {
		windows = append(windows, secondary)
	}

	var fiveHour, weekly map[string]any

	for _, w := range windows {
		secs := toFloat(w["limit_window_seconds"])
		if secs <= 0 {
			continue
		}
		if secs >= 24*3600 {
			if weekly == nil {
				weekly = w
			}
		} else {
			if fiveHour == nil {
				fiveHour = w
			}
		}
	}

	if planType == "free" {
		fiveHour = nil
		if weekly == nil && len(windows) > 0 {
			weekly = windows[0]
		}
	} else {
		if fiveHour == nil && weekly == nil {
			if len(windows) > 0 {
				fiveHour = windows[0]
			}
			if len(windows) > 1 {
				weekly = windows[1]
			}
		}
	}

	if fiveHour != nil {
		res.FiveHour = parseWindowInfo(fiveHour)
	}
	if weekly != nil {
		res.Weekly = parseWindowInfo(weekly)
	}
}

func parseWindowInfo(w map[string]any) *WindowInfo {
	return &WindowInfo{
		UsedPercent:        clampPercent(toFloat(w["used_percent"])),
		ResetAt:            int64(toFloat(w["reset_at"])),
		ResetAfterSeconds:  toFloat(w["reset_after_seconds"]),
		LimitWindowSeconds: toFloat(w["limit_window_seconds"]),
	}
}

func toFloat(v any) float64 {
	switch x := v.(type) {
	case float64:
		return x
	case int:
		return float64(x)
	case int64:
		return float64(x)
	case json.Number:
		f, _ := x.Float64()
		return f
	}
	return 0
}

func clampPercent(v float64) float64 {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return 0
	}
	if v < 0 {
		return 0
	}
	if v > 100 {
		return 100
	}
	return v
}

func formatDuration(seconds float64) string {
	if seconds <= 0 {
		return "-"
	}
	total := int(seconds)
	h := total / 3600
	m := (total % 3600) / 60
	s := total % 60
	if h > 0 {
		return fmt.Sprintf("%dh %dm", h, m)
	}
	if m > 0 {
		return fmt.Sprintf("%dm %ds", m, s)
	}
	return fmt.Sprintf("%ds", s)
}

func formatUnixTS(ts int64) string {
	if ts <= 0 {
		return "-"
	}
	return time.Unix(ts, 0).Local().Format("2006-01-02 15:04:05")
}

// printUsageResult pretty-prints a UsageResult to the terminal.
func printUsageResult(res UsageResult) {
	if res.Err != nil {
		errorf("  [ERROR] %v", res.Err)
		return
	}

	status := colorGreen("available")
	if !res.Allowed || res.LimitReached {
		status = colorRed("limited")
	}

	fmt.Printf("  status    : %s  (upstream HTTP %d)\n", status, res.UpstreamStatus)
	if res.PlanType != "" {
		fmt.Printf("  plan      : %s\n", res.PlanType)
	}

	printWindow("  5h window  ", res.FiveHour)
	printWindow("  weekly     ", res.Weekly)
}

func printWindow(label string, w *WindowInfo) {
	if w == nil {
		fmt.Printf("%s : -\n", label)
		return
	}
	bar := usageBar(w.UsedPercent)
	fmt.Printf("%s: %s remaining %.1f%% | reset at: %s | resets in: %s | window: %s\n",
		label,
		bar,
		100.00-w.UsedPercent,
		formatUnixTS(w.ResetAt),
		formatDuration(w.ResetAfterSeconds),
		formatDuration(w.LimitWindowSeconds),
	)
}

func usageBar(pct float64) string {
	const width = 20
	filled := int(pct / 100 * width)
	if filled > width {
		filled = width
	}
	bar := strings.Repeat("█", filled) + strings.Repeat("░", width-filled)
	switch {
	case pct >= 95:
		return colorRed("[" + bar + "]")
	case pct >= 80:
		return colorYellow("[" + bar + "]")
	default:
		return colorBlue("[" + bar + "]")
	}
}
