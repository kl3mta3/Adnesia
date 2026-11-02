package transparent

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"time"
)

// peekSNI reads the first TLS record from conn and extracts the server name
// (SNI) from the ClientHello, returning a connection that replays the bytes
// it consumed so the TLS handshake can proceed normally afterwards. It is how
// the transparent listener learns the hostname before deciding whether to
// intercept or to tunnel the connection through untouched.
func peekSNI(conn net.Conn) (net.Conn, string) {
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	defer conn.SetReadDeadline(time.Time{})

	hdr := make([]byte, 5)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return &replayConn{Conn: conn, r: io.MultiReader(bytes.NewReader(hdr), conn)}, ""
	}
	buf := hdr
	// 0x16 = handshake record; anything else is not TLS (or not a hello).
	if hdr[0] == 0x16 {
		n := int(binary.BigEndian.Uint16(hdr[3:5]))
		if n > 0 && n <= 1<<14+2048 {
			body := make([]byte, n)
			if _, err := io.ReadFull(conn, body); err == nil {
				buf = append(buf, body...)
				return &replayConn{Conn: conn, r: io.MultiReader(bytes.NewReader(buf), conn)}, parseSNI(body)
			}
		}
	}
	return &replayConn{Conn: conn, r: io.MultiReader(bytes.NewReader(buf), conn)}, ""
}

// replayConn serves previously-read bytes before continuing from the socket.
type replayConn struct {
	net.Conn
	r io.Reader
}

func (c *replayConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// parseSNI extracts server_name from a TLS ClientHello handshake message.
// Every length is bounds-checked; anything unexpected yields "".
func parseSNI(h []byte) string {
	// Handshake header: type(1)=1, length(3).
	if len(h) < 4 || h[0] != 0x01 {
		return ""
	}
	p := 4
	// client_version(2) + random(32)
	p += 34
	if p >= len(h) {
		return ""
	}
	// session_id
	sidLen := int(h[p])
	p += 1 + sidLen
	if p+2 > len(h) {
		return ""
	}
	// cipher_suites
	csLen := int(binary.BigEndian.Uint16(h[p:]))
	p += 2 + csLen
	if p+1 > len(h) {
		return ""
	}
	// compression_methods
	cmLen := int(h[p])
	p += 1 + cmLen
	if p+2 > len(h) {
		return ""
	}
	// extensions
	extLen := int(binary.BigEndian.Uint16(h[p:]))
	p += 2
	end := p + extLen
	if end > len(h) {
		return ""
	}
	for p+4 <= end {
		typ := binary.BigEndian.Uint16(h[p:])
		l := int(binary.BigEndian.Uint16(h[p+2:]))
		p += 4
		if p+l > end {
			return ""
		}
		if typ == 0 { // server_name
			d := h[p : p+l]
			if len(d) < 2 {
				return ""
			}
			listLen := int(binary.BigEndian.Uint16(d))
			q := 2
			for q+3 <= len(d) && q < 2+listLen {
				nameType := d[q]
				nameLen := int(binary.BigEndian.Uint16(d[q+1:]))
				q += 3
				if q+nameLen > len(d) {
					return ""
				}
				if nameType == 0 {
					return string(d[q : q+nameLen])
				}
				q += nameLen
			}
			return ""
		}
		p += l
	}
	return ""
}
