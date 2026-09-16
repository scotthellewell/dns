package blocklist

import (
	"context"
	"log"
	"sync"
	"time"
)

// Scheduler handles periodic updates of blocklist sources.
type Scheduler struct {
	manager    *Manager
	downloader *Downloader
	parser     *Parser
	stopCh     chan struct{}
	wg         sync.WaitGroup
	running    bool
	mu         sync.Mutex

	// lastAttempt records when each source was last *attempted*, as opposed
	// to BlocklistSource.LastUpdate which only advances on success. Kept in
	// memory on purpose: when a fetch was tried is a node-local fact, and
	// replicating it would make every attempt look like an entity change.
	attemptMu   sync.Mutex
	lastAttempt map[string]time.Time
}

// NewScheduler creates a new update scheduler.
func NewScheduler(manager *Manager) *Scheduler {
	return &Scheduler{
		manager:     manager,
		downloader:  NewDownloader(),
		parser:      NewParser(),
		stopCh:      make(chan struct{}),
		lastAttempt: make(map[string]time.Time),
	}
}

// Start starts the scheduler.
func (s *Scheduler) Start() {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return
	}
	s.running = true
	s.stopCh = make(chan struct{})
	s.mu.Unlock()

	// Run initial update for all sources
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.UpdateAll()
	}()

	// Start the scheduler loop
	s.wg.Add(1)
	go s.run()

	log.Printf("[blocklist-scheduler] Started")
}

// Stop stops the scheduler.
func (s *Scheduler) Stop() {
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return
	}
	s.running = false
	close(s.stopCh)
	s.mu.Unlock()

	s.wg.Wait()
	log.Printf("[blocklist-scheduler] Stopped")
}

// run is the main scheduler loop.
func (s *Scheduler) run() {
	defer s.wg.Done()

	// Check every minute for sources that need updating
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-s.stopCh:
			return
		case <-ticker.C:
			s.checkAndUpdateSources()
		}
	}
}

// checkAndUpdateSources checks all sources and updates those that need it.
func (s *Scheduler) checkAndUpdateSources() {
	sources := s.manager.GetSources()
	now := time.Now()

	for _, source := range sources {
		if !source.Enabled {
			continue
		}

		// Check if update is needed
		nextUpdate := source.LastUpdate.Add(time.Duration(source.UpdateMinutes) * time.Minute)
		if now.After(nextUpdate) && s.readyToAttempt(source.ID, source.ErrorCount, now) {
			log.Printf("[blocklist-scheduler] Source %s needs update (last: %s, interval: %dm)",
				source.ID, source.LastUpdate.Format(time.RFC3339), source.UpdateMinutes)
			go s.UpdateSource(source.ID)
		}
	}
}

// UpdateAll triggers an update for all enabled sources.
func (s *Scheduler) UpdateAll() {
	sources := s.manager.GetSources()
	var wg sync.WaitGroup

	// Limit concurrent downloads
	sem := make(chan struct{}, 3)

	for _, source := range sources {
		if !source.Enabled {
			continue
		}

		wg.Add(1)
		go func(src *Source) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			s.updateSourceWithRetry(src.ID)
		}(source)
	}

	wg.Wait()
}

// UpdateSource updates a specific source.
func (s *Scheduler) UpdateSource(sourceID string) {
	s.updateSourceWithRetry(sourceID)
}

// updateSourceWithRetry updates a source with retry logic.
func (s *Scheduler) updateSourceWithRetry(sourceID string) {
	sources := s.manager.GetSources()
	var source *Source
	for _, src := range sources {
		if src.ID == sourceID {
			source = src
			break
		}
	}
	if source == nil {
		log.Printf("[blocklist-scheduler] Source %s not found", sourceID)
		return
	}

	log.Printf("[blocklist-scheduler] Updating source: %s (%s)", source.Name, source.URL)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Download with conditional GET
	result, err := s.downloader.DownloadWithRetry(ctx, source.URL, source.LastETag, source.LastUpdate, 3)
	if err != nil {
		log.Printf("[blocklist-scheduler] Failed to download %s: %v", source.ID, err)
		s.manager.SetSourceError(sourceID, err)
		return
	}

	// Handle 304 Not Modified
	if result.NotModified {
		log.Printf("[blocklist-scheduler] Source %s not modified", source.ID)
		// Update last check time but keep entry count
		s.manager.mu.Lock()
		if src, ok := s.manager.sources[sourceID]; ok {
			src.LastUpdate = time.Now()
			src.LastError = ""
			s.manager.store.SaveBlocklistSource(src)
		}
		s.manager.mu.Unlock()
		return
	}

	// Parse the content
	parseResult := s.parser.Parse(result.Content, source.Format)
	if len(parseResult.Domains) == 0 {
		log.Printf("[blocklist-scheduler] No valid domains parsed from %s", source.ID)
		return
	}

	log.Printf("[blocklist-scheduler] Parsed %d domains from %s (lines: %d)",
		len(parseResult.Domains), source.ID, parseResult.LineCount)

	// Update the manager with new domains
	if err := s.manager.UpdateSourceDomains(sourceID, parseResult.Domains); err != nil {
		log.Printf("[blocklist-scheduler] Failed to update domains for %s: %v", sourceID, err)
		s.manager.SetSourceError(sourceID, err)
		return
	}

	// Update source metadata
	s.manager.mu.Lock()
	if src, ok := s.manager.sources[sourceID]; ok {
		src.LastUpdate = time.Now()
		src.LastETag = result.ETag
		src.EntryCount = len(parseResult.Domains)
		src.LastError = ""
		src.ErrorCount = 0
		s.manager.store.SaveBlocklistSource(src)
	}
	s.manager.mu.Unlock()

	log.Printf("[blocklist-scheduler] Successfully updated source: %s (%d domains)",
		source.Name, len(parseResult.Domains))
}

// readyToAttempt reports whether a source may be fetched now, and records the
// attempt if so.
//
// LastUpdate only advances on a successful download, so a source whose URL is
// permanently broken stays past due forever and would be retried on every
// scheduler tick - once a minute rather than once per UpdateMinutes. Each of
// those failures increments ErrorCount and writes the source back to storage,
// which replicates the change to every peer, so one dead URL produced a
// continuous cluster-wide sync storm. Back off on consecutive failures, capped
// at the source's normal interval.
func (s *Scheduler) readyToAttempt(sourceID string, errorCount int, now time.Time) bool {
	s.attemptMu.Lock()
	defer s.attemptMu.Unlock()

	if errorCount > 0 {
		shift := errorCount
		if shift > 6 {
			shift = 6
		}
		backoff := time.Duration(1<<uint(shift)) * time.Minute
		if last, ok := s.lastAttempt[sourceID]; ok && now.Before(last.Add(backoff)) {
			return false
		}
	}

	s.lastAttempt[sourceID] = now
	return true
}
