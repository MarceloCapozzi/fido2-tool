//go:build windows

package console

import "testing"

func TestIsYes(t *testing.T) {
	for _, s := range []string{"y", "Y", "yes", " YES "} {
		if !IsYes(s) {
			t.Errorf("IsYes(%q) = false, want true", s)
		}
	}
	for _, s := range []string{"", "n", "no", "yep", "s"} {
		if IsYes(s) {
			t.Errorf("IsYes(%q) = true, want false", s)
		}
	}
}

func TestQuoteArgs(t *testing.T) {
	got := QuoteArgs([]string{"rename", "--display-name", `John "JD" Doe`, ""})
	want := `rename --display-name "John \"JD\" Doe" ""`
	if got != want {
		t.Errorf("QuoteArgs = %s, want %s", got, want)
	}
}
