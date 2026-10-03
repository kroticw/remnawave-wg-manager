// Package web embeds the static page.
package web

import (
	"embed"
	"io/fs"
)

//go:embed static
var embedded embed.FS

// Static is the page served under the base path.
var Static, _ = fs.Sub(embedded, "static")
