package transparent

import (
	"encoding/binary"
	"testing"
)

// clientHello builds a minimal TLS ClientHello handshake message carrying the
// given server_name extension.
func clientHello(name string) []byte {
	var ext []byte
	// server_name extension: type 0, then list: len(2), nameType(1)=0, len(2), name
	sn := make([]byte, 2+1+2+len(name))
	binary.BigEndian.PutUint16(sn, uint16(3+len(name)))
	sn[2] = 0
	binary.BigEndian.PutUint16(sn[3:], uint16(len(name)))
	copy(sn[5:], name)
	ext = append(ext, 0, 0) // type 0
	ext = binary.BigEndian.AppendUint16(ext, uint16(len(sn)))
	ext = append(ext, sn...)

	var body []byte
	body = append(body, 3, 3)               // version
	body = append(body, make([]byte, 32)...) // random
	body = append(body, 0)                   // session id len
	body = append(body, 0, 2, 0x13, 0x01)    // one cipher suite
	body = append(body, 1, 0)                // compression: null
	body = binary.BigEndian.AppendUint16(body, uint16(len(ext)))
	body = append(body, ext...)

	msg := []byte{0x01, 0, 0, 0}
	msg[1] = byte(len(body) >> 16)
	msg[2] = byte(len(body) >> 8)
	msg[3] = byte(len(body))
	return append(msg, body...)
}

func TestParseSNI(t *testing.T) {
	if got := parseSNI(clientHello("gateway.discord.gg")); got != "gateway.discord.gg" {
		t.Errorf("parseSNI = %q, want gateway.discord.gg", got)
	}
	if got := parseSNI([]byte{0x02, 0, 0, 0}); got != "" {
		t.Errorf("non-ClientHello should yield empty, got %q", got)
	}
	if got := parseSNI(clientHello("x")[:10]); got != "" {
		t.Errorf("truncated hello should yield empty, got %q", got)
	}
}
