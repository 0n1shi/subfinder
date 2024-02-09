package dnshistory

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

type Source struct {
	timeTaken time.Duration
	errors    int
	results   int
}

var _ subscraping.Source = &Source{}

func (s *Source) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)
	s.errors = 0
	s.results = 0

	go func() {
		defer func(startTime time.Time) {
			s.timeTaken = time.Since(startTime)
			close(results)
		}(time.Now())

		page := 1
		for {
			resp, err := session.SimpleGet(ctx, fmt.Sprintf("https://dnshistory.org/subdomains/%d/%s", page, domain))
			if err != nil {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
				s.errors++
				session.DiscardHTTPResponse(resp)
				return
			}

			body, err := io.ReadAll(resp.Body)
			if err != nil {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
				s.errors++
				resp.Body.Close()
				return
			}
			resp.Body.Close()

			src := string(body)
			found := false
			for _, subdomain := range session.Extractor.Extract(src) {
				found = true
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: subdomain}
				s.results++
			}

			if !found {
				break
			}
			page++
		}
	}()

	return results
}

func (s *Source) Name() string {
	return "dnshistory"
}

func (s *Source) IsDefault() bool {
	return true
}

func (s *Source) HasRecursiveSupport() bool {
	return true
}

func (s *Source) NeedsKey() bool {
	return false
}

func (s *Source) AddApiKeys(_ []string) {
	// no key needed
}

func (s *Source) Statistics() subscraping.Statistics {
	return subscraping.Statistics{
		Errors:    s.errors,
		Results:   s.results,
		TimeTaken: s.timeTaken,
	}
}
