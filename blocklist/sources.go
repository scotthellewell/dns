package blocklist

// DefaultSources returns the default blocklist sources (Option A+).
func DefaultSources() []*Source {
	return []*Source{
		{
			ID:            "hagezi-pro",
			Name:          "Hagezi Pro",
			URL:           "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/pro.txt",
			Format:        "domains",
			Enabled:       true,
			UpdateMinutes: 720, // 12 hours
		},
		{
			ID:            "urlhaus",
			Name:          "URLhaus Malware",
			URL:           "https://urlhaus.abuse.ch/downloads/hostfile/",
			Format:        "hosts",
			Enabled:       true,
			UpdateMinutes: 30, // 30 minutes (critical security)
		},
		{
			ID:            "phishing-database",
			Name:          "Phishing Database",
			URL:           "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt",
			Format:        "domains",
			Enabled:       true,
			UpdateMinutes: 240, // 4 hours
		},
		{
			ID:            "stevenblack-porn",
			Name:          "StevenBlack Porn",
			URL:           "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/porn/hosts",
			Format:        "hosts",
			Enabled:       true,
			UpdateMinutes: 1440, // 24 hours
		},
	}
}

// AvailableSources returns all available blocklist sources that can be added.
func AvailableSources() []*SourceInfo {
	return []*SourceInfo{
		// Tier 1: Recommended
		{
			ID:          "hagezi-light",
			Name:        "Hagezi Light",
			Description: "Minimal blocking with very low breakage risk (~80K domains)",
			URL:         "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/light.txt",
			Format:      "domains",
			Category:    "general",
			Recommended: false,
		},
		{
			ID:          "hagezi-pro",
			Name:        "Hagezi Pro",
			Description: "Comprehensive blocking with low breakage risk (~350K domains)",
			URL:         "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/pro.txt",
			Format:      "domains",
			Category:    "general",
			Recommended: true,
		},
		{
			ID:          "hagezi-ultimate",
			Name:        "Hagezi Ultimate",
			Description: "Maximum blocking, may cause some breakage (~900K domains)",
			URL:         "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/ultimate.txt",
			Format:      "domains",
			Category:    "general",
			Recommended: false,
		},
		{
			ID:          "oisd-basic",
			Name:        "OISD Basic",
			Description: "Balanced blocking list (~250K domains)",
			URL:         "https://abp.oisd.nl/basic/",
			Format:      "domains",
			Category:    "general",
			Recommended: false,
		},
		{
			ID:          "oisd-full",
			Name:        "OISD Full",
			Description: "Comprehensive blocking (~1M domains)",
			URL:         "https://dbl.oisd.nl/",
			Format:      "domains",
			Category:    "general",
			Recommended: false,
		},
		{
			ID:          "stevenblack-unified",
			Name:        "StevenBlack Unified",
			Description: "Classic unified hosts file (ads + malware, ~130K domains)",
			URL:         "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
			Format:      "hosts",
			Category:    "general",
			Recommended: false,
		},

		// Tier 2: Security
		{
			ID:          "urlhaus",
			Name:        "URLhaus Malware",
			Description: "Active malware domains from abuse.ch (~15K domains)",
			URL:         "https://urlhaus.abuse.ch/downloads/hostfile/",
			Format:      "hosts",
			Category:    "security",
			Recommended: true,
		},
		{
			ID:          "phishing-database",
			Name:        "Phishing Database",
			Description: "Active phishing domains (~50K domains)",
			URL:         "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt",
			Format:      "domains",
			Category:    "security",
			Recommended: true,
		},
		{
			ID:          "threatfox",
			Name:        "ThreatFox IOCs",
			Description: "Indicators of compromise from abuse.ch",
			URL:         "https://threatfox.abuse.ch/downloads/hostfile/",
			Format:      "hosts",
			Category:    "security",
			Recommended: false,
		},

		// Tier 3: Adult Content
		{
			ID:          "stevenblack-porn",
			Name:        "StevenBlack Porn",
			Description: "Adult content blocking (~45K domains)",
			URL:         "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/porn/hosts",
			Format:      "hosts",
			Category:    "adult",
			Recommended: true,
		},
		{
			ID:          "stevenblack-porn-gambling",
			Name:        "StevenBlack Porn + Gambling",
			Description: "Adult content and gambling blocking",
			URL:         "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/porn-gambling/hosts",
			Format:      "hosts",
			Category:    "adult",
			Recommended: false,
		},

		// Tier 4: Social
		{
			ID:          "stevenblack-social",
			Name:        "StevenBlack Social",
			Description: "Social media blocking (Facebook, Twitter, etc.)",
			URL:         "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/social/hosts",
			Format:      "hosts",
			Category:    "social",
			Recommended: false,
		},

		// Tier 5: Gambling
		{
			ID:          "stevenblack-gambling",
			Name:        "StevenBlack Gambling",
			Description: "Gambling site blocking (~10K domains)",
			URL:         "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/gambling/hosts",
			Format:      "hosts",
			Category:    "gambling",
			Recommended: false,
		},

		// Tier 6: Ads/Trackers
		{
			ID:          "1hosts-lite",
			Name:        "1Hosts Lite",
			Description: "Lightweight ad blocking (~80K domains)",
			URL:         "https://o0.pages.dev/Lite/hosts.txt",
			Format:      "hosts",
			Category:    "ads",
			Recommended: false,
		},
		{
			ID:          "1hosts-pro",
			Name:        "1Hosts Pro",
			Description: "Comprehensive ad and tracker blocking (~150K domains)",
			URL:         "https://o0.pages.dev/Pro/hosts.txt",
			Format:      "hosts",
			Category:    "ads",
			Recommended: false,
		},
	}
}

// SourceInfo contains information about an available blocklist source.
type SourceInfo struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	URL         string `json:"url"`
	Format      string `json:"format"`
	Category    string `json:"category"` // general, security, adult, social, gambling, ads
	Recommended bool   `json:"recommended"`
}
