package main

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"
	"io"
)

type RenewResult struct {
	File      string
	AccountID string
	Err       error
}

func writeRenewSummary(w io.Writer, rows []RenewResult) {
	fmt.Fprintln(w, colorCyan("  [renew summary]"))
	fmt.Fprintf(w, "  %-40s  %s\n", "file", "status")
	fmt.Fprintf(w, "  %s\n", strings.Repeat("-", 55))

	ok, fail := 0, 0
	for _, r := range rows {
		label := r.File
		if r.AccountID != "" {
			label = r.AccountID
		}
		if r.Err != nil {
			fail++
			fmt.Fprintf(w, "  %-40s  %s\n", label, colorRed("ERROR: "+r.Err.Error()))
			continue
		}
		ok++
		fmt.Fprintf(w, "  %-40s  %s\n", label, colorGreen("✓ renewed"))
	}

	fmt.Fprintf(w, "  total: %d  ok: %s  fail: %s\n",
		len(rows), colorGreen(fmt.Sprintf("%d", ok)), colorRed(fmt.Sprintf("%d", fail)))
}

func renewKeyEntry(ctx context.Context, client *http.Client, entry keyEntry, tokenURL string) (*OAuthKey, error) {
	if entry.key == nil {
		return nil, fmt.Errorf("credential is nil")
	}
	if strings.TrimSpace(entry.key.RefreshToken) == "" {
		return nil, fmt.Errorf("refresh_token is empty")
	}

	refreshed, err := refreshTokenWithURL(ctx, client, entry.key.RefreshToken, tokenURL)
	if err != nil {
		return nil, err
	}

	entry.key.AccessToken = refreshed.AccessToken
	entry.key.RefreshToken = refreshed.RefreshToken
	entry.key.LastRefresh = time.Now().Format(time.RFC3339)
	entry.key.Expired = refreshed.ExpiresAt.Format(time.RFC3339)
	if strings.TrimSpace(entry.key.Type) == "" {
		entry.key.Type = "codex"
	}
	if accountID, ok := extractAccountIDFromJWT(entry.key.AccessToken); ok {
		entry.key.AccountID = accountID
	}
	if email, ok := extractEmailFromJWT(entry.key.AccessToken); ok {
		entry.key.Email = email
	}

	if err := saveKeyToFile(entry.path, entry.key); err != nil {
		return nil, err
	}
	return entry.key, nil
}
