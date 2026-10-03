package wgconf

import (
	"fmt"
	"strings"

	"rsc.io/qr"
)

const quietZone = 4

// QRSVG renders text as a QR code in SVG, one path for all dark modules.
func QRSVG(text string) (string, error) {
	code, err := qr.Encode(text, qr.M)
	if err != nil {
		return "", fmt.Errorf("qr encode: %w", err)
	}
	size := code.Size + 2*quietZone
	var path strings.Builder
	for y := 0; y < code.Size; y++ {
		for x := 0; x < code.Size; x++ {
			if code.Black(x, y) {
				fmt.Fprintf(&path, "M%d %dh1v1h-1z", x+quietZone, y+quietZone)
			}
		}
	}
	return fmt.Sprintf(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" shape-rendering="crispEdges">`+
		`<rect width="100%%" height="100%%" fill="#fff"/><path d="%s" fill="#000"/></svg>`, size, size, path.String()), nil
}
