# sasquat
```
███████╗ █████╗ ███████╗ ██████╗ ██╗   ██╗ █████╗ ████████╗
██╔════╝██╔══██╗██╔════╝██╔═══██╗██║   ██║██╔══██╗╚══██╔══╝
███████╗███████║███████╗██║   ██║██║   ██║███████║   ██║
╚════██║██╔══██║╚════██║██║▄▄ ██║██║   ██║██╔══██║   ██║
███████║██║  ██║███████║╚██████╔╝╚██████╔╝██║  ██║   ██║
╚══════╝╚═╝  ╚═╝╚══════╝ ╚══▀▀═╝  ╚═════╝ ╚═╝  ╚═╝   ╚═╝
```
A CLI tool for looking at a domain, generating typosquatting options, and verifying if they exist against DNS.

## Usage
Generate candidates for example.com, verify via DNS + TLS, output JSON lines:
`go run . -domain example.com -tlds com,net,org,co -tls=true -http=false -outfile results.json`
Include HTTP HEAD (useful to see redirect-to-login behavior), don’t follow redirects:
`go run . -domain example.com -tlds com,co,io -http=true -follow=false > results.json`

## Practical triage guidance (what to look for in results)
In the emitted JSON lines, prioritize domains that have:

- `has_mail: true` (MX records are common for phishing and BEC-like setups)
- TLS SANs containing your brand or exact target hostname patterns
- HTTP status `301/302` to a suspicious path (e.g., `/login`, `/auth`, `/microsoftonline`, etc.)
- Hosting clusters (you can extend by adding ASN/IP reputation enrichment)

## TODO
- Look for and index disparity across major DNS providers
- Also look for dangling DNS records ripe for domain and subdomain takeover

## Command-Line Flags

The sasquat CLI exposes the following flags to control domain generation scope, verification depth, concurrency, logging, and output behavior.

### Required
`-domain <string>`

Base domain to analyze for typosquatting variants.

Example: `example.com`

This domain is used as the seed for permutation generation. Only the registrable label is mutated; the original domain is not modified.

`-domain example.com`

### Optional
`-tlds <string>`

Comma-separated list of top-level domains (TLDs) to apply to generated variants.

Default: `com`

Expands the candidate set across multiple TLDs.

`-tlds com,net,org,co,io` Expanding the TLD list increases candidate volume and verification cost.

---

`-workers <int>` Number of concurrent verification workers.

Default: `runtime.NumCPU() * 4`

Controls parallel DNS, TLS, and HTTP checks.

`-workers 32` Increase cautiously to avoid DNS throttling or network saturation.

---

`-tls`

Enable TLS certificate metadata collection on port 443.

Default: `true`

Collects issuer, validity window, SANs, and common name. Certificate trust is not enforced; metadata is collected even for invalid certificates.

`-tls=true`

---

`-http`

Enable HTTP(S) HEAD request probing.

Default: `false`

Attempts HTTPS first, then HTTP as a fallback. Captures status code, redirect location, and server header.

`-http=true` No response bodies are downloaded.

---

`-follow`

Follow HTTP redirects when -http is enabled.

Default: `false`

When disabled, only the first redirect is recorded. When enabled, redirects are followed until completion or timeout.

`-follow=true` In cases of deep and numerous redirects like in common Malware rings this can really slow things down.

---

`-max <int>`

Optional cap on the number of generated candidate domains processed.

Default: `0` (no limit)

Intended primarily for testing and dry-run scenarios.

`-max 500`

---

`-log-level <string>`

Set logging verbosity.

Default: `info`

Allowed values: `debug`, `info`, `warn`, `error`

`-log-level debug` Logging output is intended for human consumption and does not affect result generation.

---

`-outfile <string>`

File path to write JSON results into.

Default: `results.json`

Results are written directly to this file rather than relying on stdout redirection.

`-outfile sasquat-results.json` Output is written in a structured JSON format suitable for ingestion into SIEM or analysis pipelines.

---

### Example Usage
```
./sasquat \
  -domain example.com \
  -tlds com,co,io \
  -workers 32 \
  -tls=true \
  -http=true \
  -log-level info \
  -outfile results.json
```
### Developer Usage
Running the tests with HTML coverage report
```bash
go test -coverpkg=./... -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```
Running the tests with minimal coverage output
`go test -cover ./...`
Just run the tests
`go test ./...`
