package adblock

import "regexp"

// compiledRegex wraps a compiled pattern with its source text so a match can
// be reported back to the operator in the form they wrote it.
type compiledRegex struct {
	pattern string
	re      *regexp.Regexp
}

func compileRegex(pattern string) (*compiledRegex, error) {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}
	return &compiledRegex{pattern: pattern, re: re}, nil
}

func (c *compiledRegex) MatchString(s string) bool { return c.re.MatchString(s) }
