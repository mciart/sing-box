package sniff

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"math"
	"os"
	"unicode/utf8"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
)

const (
	minecraftMinPacketLength  = 7
	minecraftMaxPacketLength  = 1024
	minecraftMinProtocol      = 4
	minecraftMaxProtocol      = 1_000_000
	minecraftMaxAddressLength = 255
)

// MinecraftHandshake detects a Minecraft Java Edition handshake.
//
// The first client packet is a length-prefixed handshake: packet id 0x00,
// protocol version, server address, server port, and next state
// (1 status, 2 login, 3 transfer). The TCP port is not used.
func MinecraftHandshake(_ context.Context, metadata *adapter.InboundContext, reader io.Reader) error {
	packetLength, err := readMinecraftPacketLength(reader)
	if err != nil {
		return err
	}
	if packetLength < minecraftMinPacketLength || packetLength > minecraftMaxPacketLength {
		return os.ErrInvalid
	}
	payload := make([]byte, packetLength)
	n, err := io.ReadFull(reader, payload)
	host, status := parseMinecraftHandshake(payload[:n])
	if err != nil {
		if status == minecraftNeedMore {
			return E.Cause1(ErrNeedMoreData, err)
		}
		return os.ErrInvalid
	}
	if status != minecraftOK {
		return os.ErrInvalid
	}
	metadata.Protocol = C.ProtocolMinecraft
	metadata.Domain = M.ParseSocksaddrHostPort(host, 0).Fqdn
	return nil
}

func readMinecraftPacketLength(reader io.Reader) (int, error) {
	var first [1]byte
	_, err := io.ReadFull(reader, first[:])
	if err != nil {
		return 0, E.Cause1(ErrNeedMoreData, err)
	}
	if first[0]&0x80 == 0 {
		return int(first[0]), nil
	}
	var second [1]byte
	_, err = io.ReadFull(reader, second[:])
	if err != nil {
		return 0, E.Cause1(ErrNeedMoreData, err)
	}
	if second[0]&0x80 != 0 || second[0] == 0 {
		return 0, os.ErrInvalid
	}
	return int(first[0]&0x7F) | int(second[0]&0x7F)<<7, nil
}

type minecraftParseStatus int

const (
	minecraftInvalid minecraftParseStatus = iota
	minecraftNeedMore
	minecraftOK
)

func parseMinecraftHandshake(payload []byte) (string, minecraftParseStatus) {
	if len(payload) == 0 {
		return "", minecraftNeedMore
	}
	if payload[0] != 0x00 {
		return "", minecraftInvalid
	}
	offset := 1

	version, n, status := takeMinecraftVarInt(payload[offset:])
	if status != minecraftOK {
		return "", status
	}
	if version < minecraftMinProtocol || version > minecraftMaxProtocol {
		return "", minecraftInvalid
	}
	offset += n

	addressLength, n, status := takeMinecraftVarInt(payload[offset:])
	if status != minecraftOK {
		return "", status
	}
	if addressLength < 1 || addressLength > minecraftMaxAddressLength {
		return "", minecraftInvalid
	}
	offset += n
	if len(payload)-offset < addressLength {
		if !minecraftHostPrefixOK(payload[offset:]) {
			return "", minecraftInvalid
		}
		return "", minecraftNeedMore
	}
	address := payload[offset : offset+addressLength]
	host, ok := minecraftServerName(address)
	if !ok {
		return "", minecraftInvalid
	}
	offset += addressLength

	if len(payload)-offset < 2 {
		return "", minecraftNeedMore
	}
	port := binary.BigEndian.Uint16(payload[offset:])
	offset += 2
	if port == 0 {
		return "", minecraftInvalid
	}

	state, n, status := takeMinecraftVarInt(payload[offset:])
	if status != minecraftOK {
		return "", status
	}
	if state < 1 || state > 3 {
		return "", minecraftInvalid
	}
	offset += n
	if offset != len(payload) {
		return "", minecraftInvalid
	}
	return host, minecraftOK
}

func takeMinecraftVarInt(data []byte) (int, int, minecraftParseStatus) {
	if len(data) == 0 {
		return 0, 0, minecraftNeedMore
	}
	var value uint64
	for i := 0; i < 5 && i < len(data); i++ {
		b := data[i]
		value |= uint64(b&0x7F) << (7 * i)
		if b&0x80 == 0 {
			if (i > 0 && b == 0) || value > math.MaxInt32 {
				return 0, 0, minecraftInvalid
			}
			return int(value), i + 1, minecraftOK
		}
	}
	if len(data) < 5 {
		return 0, 0, minecraftNeedMore
	}
	return 0, 0, minecraftInvalid
}

func minecraftServerName(address []byte) (string, bool) {
	host := address
	if i := bytes.IndexByte(address, 0); i >= 0 {
		host = address[:i]
	}
	if !validMinecraftHost(host) {
		return "", false
	}
	return string(host), true
}

func validMinecraftHost(host []byte) bool {
	if len(host) == 0 || !utf8.Valid(host) {
		return false
	}
	for _, c := range host {
		if c < 0x21 || c == 0x7F {
			return false
		}
	}
	return true
}

func minecraftHostPrefixOK(prefix []byte) bool {
	if len(prefix) == 0 {
		return true
	}
	if prefix[0] == 0 {
		return false
	}
	for _, c := range prefix {
		if c == 0 {
			return true
		}
		if c < 0x21 || c == 0x7F {
			return false
		}
	}
	return true
}
