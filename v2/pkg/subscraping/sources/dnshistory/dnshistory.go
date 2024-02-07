package dnshistory

import (
	"context"
	"time"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

type Source struct {
	timeTaken time.Duration
	errors    int
	results   int
}

var _ subscraping.Source = &Source{}

func (s *Source) Run(context.Context, string, *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)
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
