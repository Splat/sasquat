package verify

import (
	"context"
	"net/http"
	"reflect"
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
				result: HTTPResult{RedirectChain: []string{}},
			},
		},
		{
			name: "Test case 2: Check creation of client when HTTPFollowRedirects is false",
			args: args{
				cfg: Config{
					HTTPTimeout:         time.Second * 10,
					HTTPFollowRedirects: false,
				},
				result: HTTPResult{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := createHTTPClient(tt.args.cfg, tt.args.result)
			if got.Timeout != tt.args.cfg.HTTPTimeout {
				t.Errorf("createHTTPClient() = %v, want %v", got.Timeout, tt.args.cfg.HTTPTimeout)
			}
			req, _ := http.NewRequest("GET", "http://example.com", nil)

			if !tt.args.cfg.HTTPFollowRedirects {
				if err := got.CheckRedirect(req, []*http.Request{}); err != http.ErrUseLastResponse {
					t.Errorf("createHTTPClient() CheckRedirect expected ErrUseLastResponse")
				}
			} else {
				chainLen := len(tt.args.result.RedirectChain)
				got.CheckRedirect(req, []*http.Request{})
				if len(tt.args.result.RedirectChain) != chainLen+1 {
					t.Errorf("createHTTPClient() CheckRedirect expected to append to RedirectChain")
				}
				if tt.args.result.RedirectChain[chainLen] != req.URL.String() {
					t.Errorf("createHTTPClient() CheckRedirect expected to append correct URL to RedirectChain")
				}
			}
		})
	}
}