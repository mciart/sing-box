package sniff

import (
	"context"
	"encoding/binary"
	"io"
	"os"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	E "github.com/sagernet/sing/common/exceptions"
)

const (
	terrariaMinPacketLength = 13
	terrariaMaxPacketLength = 64
	terrariaPrefix          = "Terraria"
)

// TerrariaConnect detects a Terraria connect request.
//
// The first client packet is a little-endian length, message type 1, and a
// .NET length-prefixed version string such as "Terraria279". The TCP port is not used.
func TerrariaConnect(_ context.Context, metadata *adapter.InboundContext, reader io.Reader) error {
	var header [2]byte
	n, err := io.ReadFull(reader, header[:])
	if err != nil {
		return E.Cause1(ErrNeedMoreData, err)
	}
	if n != len(header) {
		return E.Cause1(ErrNeedMoreData, io.ErrUnexpectedEOF)
	}
	packetLength := int(binary.LittleEndian.Uint16(header[:]))
	if packetLength < terrariaMinPacketLength || packetLength > terrariaMaxPacketLength {
		return os.ErrInvalid
	}
	packet := make([]byte, packetLength)
	copy(packet, header[:])
	read, err := io.ReadFull(reader, packet[len(header):])
	version, status := parseTerrariaConnect(packet[:len(header)+read])
	if err != nil {
		if status == terrariaNeedMore {
			return E.Cause1(ErrNeedMoreData, err)
		}
		return os.ErrInvalid
	}
	if status != terrariaOK {
		return os.ErrInvalid
	}
	metadata.Protocol = C.ProtocolTerraria
	metadata.Client = version
	return nil
}

type terrariaParseStatus int

const (
	terrariaInvalid terrariaParseStatus = iota
	terrariaNeedMore
	terrariaOK
)

func parseTerrariaConnect(packet []byte) (string, terrariaParseStatus) {
	if len(packet) < 2 {
		return "", terrariaNeedMore
	}
	declared := int(binary.LittleEndian.Uint16(packet[:2]))
	if declared < terrariaMinPacketLength || declared > terrariaMaxPacketLength {
		return "", terrariaInvalid
	}
	if len(packet) < 3 {
		return "", terrariaNeedMore
	}
	if packet[2] != 1 {
		return "", terrariaInvalid
	}
	stringLength, n, status := takeTerraria7Bit(packet[3:])
	if status == terrariaNeedMore && len(packet) < declared {
		return "", terrariaNeedMore
	}
	if status != terrariaOK {
		return "", terrariaInvalid
	}
	if stringLength < len(terrariaPrefix)+1 || stringLength > declared-3-n {
		return "", terrariaInvalid
	}
	offset := 3 + n
	if len(packet) < offset+stringLength {
		if !terrariaVersionPrefixOK(packet[offset:]) {
			return "", terrariaInvalid
		}
		if len(packet) < declared {
			return "", terrariaNeedMore
		}
		return "", terrariaInvalid
	}
	version := packet[offset : offset+stringLength]
	if !terrariaVersionOK(version) {
		return "", terrariaInvalid
	}
	offset += stringLength
	if offset != declared {
		return "", terrariaInvalid
	}
	if len(packet) < declared {
		return "", terrariaNeedMore
	}
	return string(version), terrariaOK
}

func takeTerraria7Bit(data []byte) (int, int, terrariaParseStatus) {
	if len(data) == 0 {
		return 0, 0, terrariaNeedMore
	}
	var value uint64
	for i := 0; i < 5 && i < len(data); i++ {
		b := data[i]
		value |= uint64(b&0x7F) << (7 * i)
		if b&0x80 == 0 {
			if i > 0 && b == 0 {
				return 0, 0, terrariaInvalid
			}
			return int(value), i + 1, terrariaOK
		}
	}
	if len(data) < 5 {
		return 0, 0, terrariaNeedMore
	}
	return 0, 0, terrariaInvalid
}

func terrariaVersionOK(version []byte) bool {
	if len(version) <= len(terrariaPrefix) || !terrariaVersionPrefixOK(version) {
		return false
	}
	return true
}

func terrariaVersionPrefixOK(version []byte) bool {
	for i, c := range version {
		if i < len(terrariaPrefix) {
			if c != terrariaPrefix[i] {
				return false
			}
			continue
		}
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
