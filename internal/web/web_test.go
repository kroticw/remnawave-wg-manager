package web

import (
	"io/fs"
	"strings"
	"testing"
)

func read(t *testing.T, name string) string {
	t.Helper()
	b, err := fs.ReadFile(Static, name)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestNoInnerHTML(t *testing.T) {
	if strings.Contains(read(t, "app.js"), "innerHTML") || strings.Contains(read(t, "app.js"), "insertAdjacentHTML") {
		t.Fatal("app.js must not use innerHTML or insertAdjacentHTML")
	}
}

func TestNoInlineScriptsOrExternalResources(t *testing.T) {
	html := read(t, "index.html")
	for _, bad := range []string{"<script>", "onclick=", "http://", "https://", "style=\""} {
		if strings.Contains(html, bad) {
			t.Fatalf("index.html contains %q", bad)
		}
	}
}

func TestFontsAndLicensePresent(t *testing.T) {
	for _, name := range []string{"fonts/OFL.txt", "fonts/montserrat-latin-400.woff2", "fonts/montserrat-cyrillic-600.woff2"} {
		if _, err := fs.Stat(Static, name); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
}
