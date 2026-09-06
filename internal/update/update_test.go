package update

import "testing"

func TestNewer(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"1.26.0", "1.25.3", true}, {"v1.26.0", "1.25.3", true}, {"1.25.3", "1.25.3", false},
		{"1.25.2", "1.25.3", false}, {"2.0.0", "1.99.99", true}, {"1.25.10", "1.25.9", true},
		{"1.26.0", "dev", false}, {"dev", "1.25.3", false}, {"1.26.0-rc1", "1.25.3", true},
	}
	for _, c := range cases {
		if got := Newer(c.a, c.b); got != c.want {
			t.Errorf("Newer(%q, %q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}
