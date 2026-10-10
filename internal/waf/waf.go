package waf

import (
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/mohit-bhandari45/bastion/internal/config"
)

type Engine struct {
	cfg      *config.WAFConfig
	patterns []*regexp.Regexp
}

func New(cfg *config.WAFConfig) (*Engine, error) {
	e := &Engine{cfg: cfg}
	for _, p := range cfg.BlockedPatterns {
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, err
		}
		e.patterns = append(e.patterns, re)
	}
	return e, nil
}

type MatchResult struct {
	Matched bool
	Reason  string
	Pattern string
}

func (e *Engine) Inspect(r *http.Request) MatchResult {
	if !e.cfg.Enabled {
		return MatchResult{Matched: false}
	}

	// 1. Check URL path + query
	rawURL := r.URL.RequestURI()
	if decoded, err := url.QueryUnescape(rawURL); err == nil {
		rawURL = decoded
	}
	if res := e.match(rawURL); res.Matched {
		res.Reason = "malicious pattern in URL"
		return res
	}

	// 2. Check common headers
	for _, h := range []string{"User-Agent", "Referer", "X-Forwarded-For"} {
		if res := e.match(r.Header.Get(h)); res.Matched {
			res.Reason = "malicious pattern in header: " + h
			return res
		}
	}

	// 3. Check body (limited size)
	if r.Body != nil && r.ContentLength > 0 && r.ContentLength < e.cfg.MaxBodySize {
		body, err := io.ReadAll(io.LimitReader(r.Body, e.cfg.MaxBodySize))
		if err == nil {
			// Restore body for upstream
			r.Body = io.NopCloser(strings.NewReader(string(body)))
			if res := e.match(string(body)); res.Matched {
				res.Reason = "malicious pattern in body"
				return res
			}
		}
	}

	return MatchResult{Matched: false}
}

func (e *Engine) match(input string) MatchResult {
	for _, re := range e.patterns {
		if re.MatchString(input) {
			return MatchResult{
				Matched: true,
				Pattern: re.String(),
			}
		}
	}
	return MatchResult{Matched: false}
}
