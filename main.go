package main

import (
	"context"
	"encoding/json"
	"flag"
	"log"
	"log/slog"
	"os"
	"runtime"
	"squatrr/lib/banner"
	"squatrr/lib/typo"
	"squatrr/lib/verify"
	"strings"
	"sync"
	"time"
)

type Output struct {
	Domain     string             `json:"domain"`
	Resolvable bool               `json:"resolvable"`
	HasMail    bool               `json:"has_mail"`
	DNS        verify.DNSResult   `json:"dns"`
	TLS        *verify.TLSResult  `json:"tls,omitempty"`
	HTTP       *verify.HTTPResult `json:"http,omitempty"`
}

func main() {
	banner.PrintBanner()

	var (
		domain     = flag.String("domain", "", "Base domain, e.g., example.com")
		tlds       = flag.String("tlds", "com", "Comma-separated TLD variants, e.g., com,net,org,co,io")
		workers    = flag.Int("workers", runtime.NumCPU()*4, "Concurrent verification workers")
		doTLS      = flag.Bool("tls", true, "Attempt TLS metadata fetch on :443")
		doHTTP     = flag.Bool("http", false, "Attempt HTTP(S) HEAD request")
		follow     = flag.Bool("follow", false, "Follow HTTP redirects")
		maxDomains = flag.Int("max", 0, "Optional(testing) cap on number of candidates processed (0 = no cap)")
		logLevel   = flag.String("log-level", "info", "debug|info|warn|error")
		outfile    = flag.String("outfile", "site/data/results.json", "Output file to write results into. Default is 'site/data/results.json' for website")
	)
	flag.Parse()

	// configure the logger to keep logs separate from output
	level := parseLogLevel(*logLevel)
	handler := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: level})
	logger := slog.New(handler) //.With("component")

	// Used in verify to loop through top level domains.
	tldsOverride := parseTLDs(*domain, *tlds)
	for _, tld := range tldsOverride {
		logger.Info("processing tldOverride", "queued", tld)
	}

	if *domain == "" {
		logger.Error("error: -domain is required")
		os.Exit(2)
	}

	var candidates, err = typo.Generate(*domain, nil, *logger)
	if err != nil {
		logger.Error("processing candidates", "error", err)
		os.Exit(2)
	}

	permutationCount := 0
	for _, d := range candidates {
		logger.Debug("processing candidates main", "strategy", d.StrategyName, "count", len(d.Permutations))
		permutationCount += len(d.Permutations)
	}
	logger.Info("processing candidates main", "count", permutationCount*len(tldsOverride))

	// TODO: this is wrong, as is limits on strategies not permutations
	if *maxDomains > 0 && *maxDomains < len(candidates) {
		candidates = candidates[:*maxDomains]
	}

	vCfg := verify.Config{
		DNSTimeout:          2 * time.Second,
		TLSTimeout:          3 * time.Second,
		HTTPTimeout:         4 * time.Second,
		DoTLS:               *doTLS,
		DoHTTP:              *doHTTP,
		HTTPFollowRedirects: *follow,
		UserAgent:           "saskquat-verifier/1.0",
	}

	ctx := context.Background()

	in := make(chan string)
	out := make(chan Output)

	var wg sync.WaitGroup
	for i := 0; i < *workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for d := range in {
				for _, tld := range tldsOverride {
					v, err := verify.VerifyDomain(ctx, d+"."+tld, vCfg)
					if err != nil {
						continue
					}
					// Simple triage: only emit domains that show signs of being “real”
					if !v.Resolvable && !v.HasMail {
						continue
					}

					out <- Output{
						Domain:     v.ASCII,
						Resolvable: v.Resolvable,
						HasMail:    v.HasMail,
						DNS:        v.DNS,
						TLS:        v.TLS,
						HTTP:       v.HTTP,
					}
				}
			}
		}()
	}

	go func() {
		for _, d := range candidates {
			for _, p := range d.Permutations {
				in <- p // the actual typo permutation
			}
		}
		close(in)
		wg.Wait()
		close(out)
	}()

	// Create the output file
	file, err := os.Create(*outfile)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)

	// To write as a single JSON array, we collect all items into a slice first.
	// For truly massive streams, you would manually write the `[` and `]` characters
	// and handle commas between individual object encodes.
	var allData []Output
	for dnsResult := range out {
		allData = append(allData, dnsResult)
	}
	logger.Info("processing completed main", slog.Int("found", len(allData)))

	wg.Wait()

	if err := encoder.Encode(allData); err != nil {
		log.Fatal(err)
	}

	// TODO: IF outfile == "site/data/results.json" launch site/home.html
	if *outfile == "site/data/results.json" {
		// Launch site/home.html
	} else {
		// either write to console or try to pass path in as a parameter
		// change the site to accept a query parameter for file to load
	}
}

func parseTLDs(domain, override string) []string {
	if override != "" {
		parts := strings.Split(override, ",")
		var tlds []string
		for _, p := range parts {
			if v := strings.TrimSpace(p); v != "" {
				tlds = append(tlds, v)
			}
		}
		return tlds
	}

	for i := len(domain) - 1; i >= 0; i-- {
		if domain[i] == '.' && i < len(domain)-1 {
			return []string{domain[i+1:]}
		}
	}
	return []string{"com"}
}

func parseLogLevel(s string) slog.Level {
	switch s {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
