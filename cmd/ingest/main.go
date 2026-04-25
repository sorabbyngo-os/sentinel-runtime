package main

import (
	"log"
	"os"
)

var logger = log.New(os.Stdout, "[INGEST] ", log.LstdFlags)

func main() {
	logger.Println("sentinel-runtime ingest — reads kernel events from /proc and eBPF")
	logger.Println("Phase 2: will replace Python KCP watcher with native Go eBPF")
	logger.Println("Current: defer to Python sentinel_watcher.py for eBPF events")
}
