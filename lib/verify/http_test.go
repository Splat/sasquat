package verify

import (
	"net/http"
	"testing"
	"time"
)

func TestCreateHTTPClient(t *testing.T) {
	type args struct {
		cfg    Config
		result HTTPResult
	}

	tests := []struct {
		name string
		args args
		want http.Client
	}{
		{
			name: "Test case 1: Check creation of client when HTTPFollowRedirects is true",
			args: args{
				cfg: Config{
					HTTPTimeout:         time.Second * 5,
					HTTPFollowRedirects: true,
				},
				result: HTTPResult{RedirectChain: []string{"redirect1.test", "redirect2.test"}},
			},
		},
		{
			name: "Test case 2: Check creation of client when HTTPFollowRedirects is false",
			args: args{
				cfg: Config{
					HTTPTimeout:         time.Second * 10,
					HTTPFollowRedirects: false,
				},
				result: HTTPResult{RedirectChain: []string{}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := configureHTTPClient(tt.args.cfg, tt.args.result)
			if got.Timeout != tt.args.cfg.HTTPTimeout {
				t.Errorf("createHTTPClient() = %v, want %v", got.Timeout, tt.args.cfg.HTTPTimeout)
			}
			// note really sure how to test the redirect chain code or if necessary
			req, _ := http.NewRequest("GET", "http://example.com", nil)

			if !tt.args.cfg.HTTPFollowRedirects {
				if err := got.CheckRedirect(req, []*http.Request{}); err != http.ErrUseLastResponse {
					t.Errorf("createHTTPClient() CheckRedirect expected ErrUseLastResponse")
				}
			} else {
				// ensures the function instantiated and isn't the error response to not follow
				if err := got.CheckRedirect(req, []*http.Request{{URL: req.URL}}); err != nil {
					t.Errorf("createHTTPClient() CheckRedirect error: %v", err)
				}
			}
		})
	}
}
