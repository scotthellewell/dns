package blocklist

import (
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Downloader handles fetching blocklists from URLs with caching support.
type Downloader struct {
	client      *http.Client
	userAgent   string
	maxSize     int64 // Maximum download size in bytes
	timeout     time.Duration
}

// DownloadResult contains the result of a download operation.
type DownloadResult struct {
	Content     string
	ETag        string
	LastModTime time.Time
	StatusCode  int
	NotModified bool
}

// NewDownloader creates a new blocklist downloader.
func NewDownloader() *Downloader {
	return &Downloader{
		client: &http.Client{
			Timeout: 60 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:        10,
				IdleConnTimeout:     30 * time.Second,
				DisableCompression:  false,
				DisableKeepAlives:   false,
			},
		},
		userAgent: "DNS-Blocklist-Fetcher/1.0",
		maxSize:   100 * 1024 * 1024, // 100MB max
		timeout:   60 * time.Second,
	}
}

// Download fetches a blocklist from the given URL.
// If etag or lastModified are provided, conditional GET is performed.
func (d *Downloader) Download(ctx context.Context, url string, etag string, lastModified time.Time) (*DownloadResult, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	req.Header.Set("User-Agent", d.userAgent)
	req.Header.Set("Accept-Encoding", "gzip")
	req.Header.Set("Accept", "text/plain, application/octet-stream, */*")

	// Conditional GET headers
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	if !lastModified.IsZero() {
		req.Header.Set("If-Modified-Since", lastModified.UTC().Format(http.TimeFormat))
	}

	resp, err := d.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch: %w", err)
	}
	defer resp.Body.Close()

	result := &DownloadResult{
		StatusCode: resp.StatusCode,
	}

	// Handle 304 Not Modified
	if resp.StatusCode == http.StatusNotModified {
		result.NotModified = true
		return result, nil
	}

	// Check for errors
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, resp.Status)
	}

	// Get response metadata
	if e := resp.Header.Get("ETag"); e != "" {
		result.ETag = e
	}
	if lm := resp.Header.Get("Last-Modified"); lm != "" {
		if t, err := http.ParseTime(lm); err == nil {
			result.LastModTime = t
		}
	}

	// Read body with size limit
	var reader io.Reader = resp.Body

	// Handle gzip compression
	if resp.Header.Get("Content-Encoding") == "gzip" {
		gzReader, err := gzip.NewReader(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to create gzip reader: %w", err)
		}
		defer gzReader.Close()
		reader = gzReader
	}

	// Read with size limit
	limitedReader := io.LimitReader(reader, d.maxSize)
	content, err := io.ReadAll(limitedReader)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	result.Content = string(content)
	return result, nil
}

// DownloadWithRetry downloads with automatic retries on failure.
func (d *Downloader) DownloadWithRetry(ctx context.Context, url string, etag string, lastModified time.Time, maxRetries int) (*DownloadResult, error) {
	var lastErr error

	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			// Exponential backoff: 1s, 2s, 4s, 8s...
			backoff := time.Duration(1<<uint(attempt-1)) * time.Second
			if backoff > 30*time.Second {
				backoff = 30 * time.Second
			}
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoff):
			}
		}

		result, err := d.Download(ctx, url, etag, lastModified)
		if err == nil {
			return result, nil
		}

		lastErr = err
		// Don't retry on certain errors
		if strings.Contains(err.Error(), "HTTP 4") {
			return nil, err // 4xx errors are not retryable
		}
	}

	return nil, fmt.Errorf("download failed after %d retries: %w", maxRetries, lastErr)
}

// SetUserAgent sets the User-Agent header for requests.
func (d *Downloader) SetUserAgent(ua string) {
	d.userAgent = ua
}

// SetMaxSize sets the maximum download size in bytes.
func (d *Downloader) SetMaxSize(size int64) {
	d.maxSize = size
}

// SetTimeout sets the request timeout.
func (d *Downloader) SetTimeout(timeout time.Duration) {
	d.timeout = timeout
	d.client.Timeout = timeout
}
