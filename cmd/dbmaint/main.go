// Package main provides database maintenance utilities
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"strings"

	"github.com/scott/dns/storage"
)

func main() {
	dataDir := flag.String("data", "./data", "Data directory path")
	dryRun := flag.Bool("dry-run", true, "Don't make changes, just show what would be fixed")
	setSerial := flag.Uint("set-serial", 0, "Set serial number for all zones (0 = skip)")
	zoneName := flag.String("zone", "", "Zone name to update serial (empty = all zones)")
	showSerials := flag.Bool("show-serials", false, "Show current serial numbers for all zones")
	flag.Parse()

	store, err := storage.Open(storage.Options{DataDir: *dataDir})
	if err != nil {
		log.Fatalf("Failed to open storage: %v", err)
	}
	defer store.Close()

	fmt.Println("Database Maintenance Tool")
	fmt.Println("=========================")
	if *dryRun {
		fmt.Println("DRY RUN MODE - no changes will be made")
	}
	fmt.Println()

	// Show serials if requested
	if *showSerials {
		showZoneSerials(store)
		return
	}

	// Set serial if requested
	if *setSerial > 0 {
		setZoneSerial(store, *zoneName, uint32(*setSerial), *dryRun)
		return
	}

	// Default: audit and fix records
	auditAndFixRecords(store, *dryRun)
}

func showZoneSerials(store *storage.Store) {
	zones, err := store.ListZones("")
	if err != nil {
		log.Fatalf("Failed to list zones: %v", err)
	}

	fmt.Println("Zone Serial Numbers:")
	fmt.Println("--------------------")
	for _, zone := range zones {
		fmt.Printf("  %s: %d\n", zone.Name, zone.Serial)
	}
}

func setZoneSerial(store *storage.Store, zoneName string, serial uint32, dryRun bool) {
	zones, err := store.ListZones("")
	if err != nil {
		log.Fatalf("Failed to list zones: %v", err)
	}

	for _, zone := range zones {
		if zoneName != "" && zone.Name != zoneName {
			continue
		}

		if zone.Serial == serial {
			fmt.Printf("  %s: already at serial %d\n", zone.Name, serial)
			continue
		}

		fmt.Printf("  %s: %d -> %d", zone.Name, zone.Serial, serial)

		if dryRun {
			fmt.Println(" (dry run)")
			continue
		}

		zone.Serial = serial
		if err := store.UpdateZonePreserveSerial(zone); err != nil {
			fmt.Printf(" ERROR: %v\n", err)
		} else {
			fmt.Println(" OK")
		}
	}
}

func auditAndFixRecords(store *storage.Store, dryRun bool) {
	zones, err := store.ListZones("")
	if err != nil {
		log.Fatalf("Failed to list zones: %v", err)
	}

	issuesFound := 0
	issuesFixed := 0

	for _, zone := range zones {
		records, err := store.GetAllZoneRecords(zone.Name)
		if err != nil {
			log.Printf("Error loading records for zone %s: %v", zone.Name, err)
			continue
		}

		fmt.Printf("\n--- Zone: %s (%d records) ---\n", zone.Name, len(records))

		for _, rec := range records {
			issues := []string{}

			// Check 1: Name contains zone name (doubled zone)
			if strings.Contains(rec.Name, zone.Name) && rec.Name != "@" {
				issues = append(issues, fmt.Sprintf("name contains zone (%s)", rec.Name))
			}

			// Check 2: Whitespace in A/AAAA record IP
			if rec.Type == "A" || rec.Type == "AAAA" {
				var data map[string]string
				if err := json.Unmarshal(rec.Data, &data); err == nil {
					ip := data["ip"]
					if ip == "" {
						ip = data["address"]
					}
					if ip != strings.TrimSpace(ip) {
						issues = append(issues, fmt.Sprintf("whitespace in IP: '%s'", ip))
					}
				}
			}

			// Check 3: Empty or invalid data
			if len(rec.Data) == 0 || string(rec.Data) == "{}" || string(rec.Data) == "null" {
				issues = append(issues, "empty data")
			}

			// Check 4: Name has leading/trailing whitespace
			if rec.Name != strings.TrimSpace(rec.Name) {
				issues = append(issues, fmt.Sprintf("whitespace in name: '%s'", rec.Name))
			}

			if len(issues) > 0 {
				issuesFound++
				fmt.Printf("  [ISSUE] %s %s %s\n", rec.Name, rec.Type, rec.ID)
				for _, issue := range issues {
					fmt.Printf("          - %s\n", issue)
				}

				if !dryRun {
					if fixRecord(store, zone.Name, &rec) {
						issuesFixed++
						fmt.Printf("          > FIXED\n")
					} else {
						fmt.Printf("          > COULD NOT FIX\n")
					}
				}
			}
		}
	}

	fmt.Printf("\n=========================\n")
	fmt.Printf("Issues found: %d\n", issuesFound)
	if !dryRun {
		fmt.Printf("Issues fixed: %d\n", issuesFixed)
	}
}

func fixRecord(store *storage.Store, zoneName string, rec *storage.Record) bool {
	changed := false

	// Fix 1: Name contains zone name - delete old and create corrected
	if strings.Contains(rec.Name, zoneName) && rec.Name != "@" {
		newName := strings.TrimSuffix(rec.Name, "."+zoneName)
		newName = strings.TrimSuffix(newName, zoneName)
		newName = strings.TrimSuffix(newName, ".")

		// If the result is empty, it was an apex record - use @
		if newName == "" {
			newName = "@"
		}

		if newName != rec.Name {
			log.Printf("Fixing name: %s -> %s", rec.Name, newName)

			if err := store.DeleteRecord(rec.Zone, rec.Name, rec.Type, rec.ID); err != nil {
				log.Printf("Failed to delete old record: %v", err)
				return false
			}

			rec.Name = newName
			if err := store.CreateRecord(rec); err != nil {
				log.Printf("Failed to create corrected record: %v", err)
				return false
			}
			changed = true
		}
	}

	// Fix 2: Whitespace in IP - update the record data
	if rec.Type == "A" || rec.Type == "AAAA" {
		var data map[string]string
		if err := json.Unmarshal(rec.Data, &data); err == nil {
			ip := data["ip"]
			field := "ip"
			if ip == "" {
				ip = data["address"]
				field = "address"
			}
			trimmed := strings.TrimSpace(ip)
			if ip != trimmed {
				log.Printf("Fixing IP whitespace: '%s' -> '%s'", ip, trimmed)
				data[field] = trimmed
				newData, _ := json.Marshal(data)
				rec.Data = newData
				if err := store.UpdateRecord(rec); err != nil {
					log.Printf("Failed to update record: %v", err)
					return false
				}
				changed = true
			}
		}
	}

	// Fix 3: Whitespace in name - delete old and create corrected
	trimmedName := strings.TrimSpace(rec.Name)
	if rec.Name != trimmedName && trimmedName != "" {
		log.Printf("Fixing name whitespace: '%s' -> '%s'", rec.Name, trimmedName)

		if err := store.DeleteRecord(rec.Zone, rec.Name, rec.Type, rec.ID); err != nil {
			log.Printf("Failed to delete old record: %v", err)
			return false
		}

		rec.Name = trimmedName
		if err := store.CreateRecord(rec); err != nil {
			log.Printf("Failed to create corrected record: %v", err)
			return false
		}
		changed = true
	}

	return changed
}
