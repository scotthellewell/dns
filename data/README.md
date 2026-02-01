# Data Directory

This directory contains runtime data for the DNS server. The database file is not committed to git.

## Files

- `data.db` - bbolt database containing all configuration, zones, records, users, sessions, and DNSSEC keys

## Backup

To backup the DNS server data, simply copy the `data.db` file while the server is stopped, or use the API backup endpoint.
