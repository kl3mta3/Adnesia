package update

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewer(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"1.0.0", "0.9.0", true},
		{"v1.0.0", "0.9.0", true},
		{"0.9.0", "1.0.0", false},
		{"0.9.0", "0.9.0", false},
		{"0.9.1", "0.9.0", true},
		{"0.10.0", "0.9.0", true},
		{"1.0", "0.9.0", true},
		{"1.0.0", "1.0.0-rc1", true},
		{"1.0.0-rc1", "1.0.0", false},
		{"1.0.0-rc2", "1.0.0-rc1", true},
		{"junk", "0.9.0", false},
	}
	for _, c := range cases {
		if got := Newer(c.a, c.b); got != c.want {
			t.Errorf("Newer(%q,%q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestCheckFindsNewerRelease(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/kl3mta3/Adnesia/releases/latest" {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("User-Agent") == "" {
			t.Error("GitHub requires a User-Agent")
		}
		_, _ = w.Write([]byte(`{"tag_name":"v1.0.0","html_url":"https://github.com/kl3mta3/Adnesia/releases/tag/v1.0.0"}`))
	}))
	defer srv.Close()

	c := New("kl3mta3", "Adnesia", "0.9.0", srv.URL, quiet())
	st := c.Check(context.Background())
	if st.Error != "" || !st.Available || st.Latest != "1.0.0" || st.URL == "" || st.LastChecked.IsZero() {
		t.Fatalf("unexpected status: %+v", st)
	}
	if c.Status() != st {
		t.Error("Status() should return the last result")
	}
}

func TestCheckSameVersionNotAvailable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"tag_name":"0.9.0","html_url":"u"}`))
	}))
	defer srv.Close()
	st := New("o", "r", "v0.9.0", srv.URL, quiet()).Check(context.Background())
	if st.Available || st.Error != "" || st.Latest != "0.9.0" {
		t.Fatalf("unexpected: %+v", st)
	}
}

func TestCheckNoReleaseYet(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()
	st := New("o", "r", "0.9.0", srv.URL, quiet()).Check(context.Background())
	if st.Available || st.Error != ErrNoRelease.Error() {
		t.Fatalf("unexpected: %+v", st)
	}
}

func TestCheckServerErrorKeepsPreviousResult(t *testing.T) {
	fail := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fail {
			http.Error(w, "rate limited", http.StatusForbidden)
			return
		}
		_, _ = w.Write([]byte(`{"tag_name":"v1.2.0","html_url":"u"}`))
	}))
	defer srv.Close()
	c := New("o", "r", "0.9.0", srv.URL, quiet())
	c.Check(context.Background())
	fail = true
	st := c.Check(context.Background())
	if st.Error == "" || !st.Available || st.Latest != "1.2.0" {
		t.Fatalf("a failed check must keep the last good result: %+v", st)
	}
}
