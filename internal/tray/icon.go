package tray

import (
	"bytes"
	_ "embed"
	"encoding/binary"
	"image"
	"image/color"
	"math"
)

//go:embed appicon.ico
var appIcon []byte

// iconICO returns the tray icon: the project's own .ico when present,
// otherwise a generated fallback (a blue disc with a white "no" slash).
func iconICO() []byte {
	if len(appIcon) > 0 {
		return appIcon
	}
	const n = 32
	img := drawIcon(n)
	return encodeICO(img)
}

func drawIcon(n int) *image.RGBA {
	img := image.NewRGBA(image.Rect(0, 0, n, n))
	cx, cy := float64(n-1)/2, float64(n-1)/2
	r := float64(n)/2 - 1.5
	blue := color.RGBA{0x2d, 0x9c, 0xdb, 0xff}
	white := color.RGBA{0xff, 0xff, 0xff, 0xff}

	for y := 0; y < n; y++ {
		for x := 0; x < n; x++ {
			dx, dy := float64(x)-cx, float64(y)-cy
			dist := math.Hypot(dx, dy)
			if dist > r {
				continue // transparent outside the disc
			}
			// The "ban" slash: a thick diagonal band near x==y.
			if math.Abs(dx-dy) < 2.6 && dist < r-2 {
				img.Set(x, y, white)
			} else {
				img.Set(x, y, blue)
			}
		}
	}
	return img
}

// encodeICO encodes a single RGBA image as a 32-bpp Windows .ico.
func encodeICO(img *image.RGBA) []byte {
	b := img.Bounds()
	w, h := b.Dx(), b.Dy()

	xorStride := w * 4
	andStride := ((w + 31) / 32) * 4 // AND mask rows padded to 32 bits
	pixelBytes := xorStride*h + andStride*h
	dibSize := 40 + pixelBytes

	var buf bytes.Buffer
	le := binary.LittleEndian
	wr := func(v any) { _ = binary.Write(&buf, le, v) }

	// ICONDIR
	wr(uint16(0)) // reserved
	wr(uint16(1)) // type: icon
	wr(uint16(1)) // count
	// ICONDIRENTRY
	buf.WriteByte(byte(w % 256)) // width (0 == 256)
	buf.WriteByte(byte(h % 256)) // height
	buf.WriteByte(0)             // palette count
	buf.WriteByte(0)             // reserved
	wr(uint16(1))                // color planes
	wr(uint16(32))               // bits per pixel
	wr(uint32(dibSize))          // size of DIB
	wr(uint32(22))               // offset to DIB (6 + 16)

	// BITMAPINFOHEADER
	wr(uint32(40))         // header size
	wr(int32(w))           // width
	wr(int32(h * 2))       // height (XOR + AND)
	wr(uint16(1))          // planes
	wr(uint16(32))         // bpp
	wr(uint32(0))          // compression BI_RGB
	wr(uint32(pixelBytes)) // image size
	wr(int32(0))           // x ppm
	wr(int32(0))           // y ppm
	wr(uint32(0))          // colors used
	wr(uint32(0))          // colors important

	// XOR pixel data, bottom-up, BGRA.
	for y := h - 1; y >= 0; y-- {
		for x := 0; x < w; x++ {
			c := img.RGBAAt(b.Min.X+x, b.Min.Y+y)
			buf.WriteByte(c.B)
			buf.WriteByte(c.G)
			buf.WriteByte(c.R)
			buf.WriteByte(c.A)
		}
	}
	// AND mask: all zero (transparency comes from the alpha channel).
	buf.Write(make([]byte, andStride*h))

	return buf.Bytes()
}
