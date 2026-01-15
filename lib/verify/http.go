package verify

import (
	"context"
	"fmt"
	"net/http"
)

type HTTPResult struct {
	Attempted     bool
	URL           string
	Status        string
	StatusCode    int
	Location      string
	Server        string
	RedirectChain []string
	// TODO: For fast lookup downstream
	// TODO: HasRedirect 	bool
	// TODO: Remediated 	bool // validate last redirect == Verification.Domain
}

// generateHTTPResult initializes an HTTPResult struct with attempted flag set to true and an empty RedirectChain.
// The URL field is set to the target domain after extracting it from the provided domain string.
// should probably be an init method on the HTTPResult type
func generateHTTPResult(https bool, domain string) HTTPResult {
	res := HTTPResult{Attempted: true, RedirectChain: []string{}}
	target := getTargetDomain(https, domain)
	res.URL = target

	return res
}

func configureHTTPClient(cfg Config, result HTTPResult) http.Client {
	client := &http.Client{
		Timeout: cfg.HTTPTimeout,
	}

	if !cfg.HTTPFollowRedirects { // don't follow the redirects and short circuit
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	} else { // follow redirects to a maximum of 10 (might change in the future)
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("stopped after 10 redirects")
			}
			result.RedirectChain = append(result.RedirectChain, req.URL.String())
			return nil
		}
	}
	return *client
}

// fetchHTTP executes the provided domain and returns the HTTPResult
// The last item in the HTTPResult.RedirectChain array is the final landing spot.
func fetchHTTP(ctx context.Context, https bool, domain string, cfg Config) HTTPResult {
	res := generateHTTPResult(https, domain)
	client := configureHTTPClient(cfg, res)

	req, err := http.NewRequestWithContext(ctx, http.MethodHead, res.URL, nil)
	if err != nil {
		return res
	}
	req.Header.Set("User-Agent", cfg.UserAgent)

	// TODO: Factor this out to a processHTTP method to compliment this fetchHTTP for unit testing
	resp, err := client.Do(req)
	if err != nil && https { // If HTTPS fails, try HTTP as a fallback.
		// TODO: recall fetchHTTP without HTTPS to reduce code
		// TODO: attempted above but getting weird nil ptr issues and couldn't figure out so bailed
		res.URL = getTargetDomain(false, domain)
		req2, err2 := http.NewRequestWithContext(ctx, http.MethodHead, res.URL, nil)
		if err2 != nil {
			return res
		}
		req2.Header.Set("User-Agent", cfg.UserAgent)
		resp2, err2 := client.Do(req2)
		if err2 != nil {
			return res
		}
		defer resp2.Body.Close()
		res.Status = resp2.Status
		res.StatusCode = resp2.StatusCode
		res.Location = resp2.Header.Get("Location")
		res.Server = resp2.Header.Get("Server")
		return res
	}

	res.Status = resp.Status
	res.StatusCode = resp.StatusCode
	res.Location = resp.Header.Get("Location")
	res.Server = resp.Header.Get("Server")
	return res
}
