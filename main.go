package main

import (
	"flag"
	"log"
	"path/filepath"

	"github.com/fsnotify/fsnotify"
	"github.com/scott/dns/config"
	"github.com/scott/dns/server"
)

func main() {
	configPath := flag.String("config", "config.json", "Path to configuration file")
	flag.Parse()

	log.Printf("Loading configuration from %s", *configPath)
	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	parsed, err := cfg.Parse()
	if err != nil {
		log.Fatalf("Failed to parse configuration: %v", err)
	}

	log.Printf("Configured %d zones", len(parsed.Zones))

	srv := server.New(parsed)

	// Start config file watcher
	go watchConfig(*configPath, srv)

	if err := srv.Start(); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

func watchConfig(configPath string, srv *server.Server) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Printf("Failed to create config watcher: %v", err)
		return
	}
	defer watcher.Close()

	// Watch the directory containing the config file
	// This is more reliable than watching the file directly
	configDir := filepath.Dir(configPath)
	configFile := filepath.Base(configPath)

	if err := watcher.Add(configDir); err != nil {
		log.Printf("Failed to watch config directory: %v", err)
		return
	}

	log.Printf("Watching %s for changes", configPath)

	for {
		select {
		case event, ok := <-watcher.Events:
			if !ok {
				return
			}
			// Check if it's our config file and it was written/created
			if filepath.Base(event.Name) == configFile {
				if event.Op&(fsnotify.Write|fsnotify.Create) != 0 {
					log.Printf("Config file changed, reloading...")
					reloadConfig(configPath, srv)
				}
			}
		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			log.Printf("Config watcher error: %v", err)
		}
	}
}

func reloadConfig(configPath string, srv *server.Server) {
	cfg, err := config.Load(configPath)
	if err != nil {
		log.Printf("Failed to load config: %v", err)
		return
	}

	parsed, err := cfg.Parse()
	if err != nil {
		log.Printf("Failed to parse config: %v", err)
		return
	}

	srv.UpdateConfig(parsed)
}