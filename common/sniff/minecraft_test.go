package sniff_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/sniff"
	C "github.com/sagernet/sing-box/constant"

	"github.com/stretchr/testify/require"
)

func TestSniffMinecraftHandshake(t *testing.T) {
	t.Parallel()

	pkt := minecraftHandshakePacket(767, "play.example.com", 25565, 2)
	var metadata adapter.InboundContext
	err := sniff.MinecraftHandshake(context.Background(), &metadata, bytes.NewReader(pkt))
	require.NoError(t, err)
	require.Equal(t, C.ProtocolMinecraft, metadata.Protocol)
	require.Equal(t, "play.example.com", metadata.Domain)
}

func TestSniffMinecraftHandshakeAnyPort(t *testing.T) {
	t.Parallel()

	pkt := minecraftHandshakePacket(777, "localhost", 30000, 1)
	var metadata adapter.InboundContext
	err := sniff.MinecraftHandshake(context.Background(), &metadata, bytes.NewReader(append(pkt, 0x01, 0x00)))
	require.NoError(t, err)
	require.Equal(t, C.ProtocolMinecraft, metadata.Protocol)
	require.Equal(t, "localhost", metadata.Domain)
}

func TestSniffMinecraftTransferAndForgeAddress(t *testing.T) {
	t.Parallel()

	pkt := minecraftHandshakePacket(340, "mc.example.com\x00FML\x00", 19132, 3)
	var metadata adapter.InboundContext
	err := sniff.MinecraftHandshake(context.Background(), &metadata, bytes.NewReader(pkt))
	require.NoError(t, err)
	require.Equal(t, C.ProtocolMinecraft, metadata.Protocol)
	require.Equal(t, "mc.example.com", metadata.Domain)
}

func TestSniffMinecraftIPAddress(t *testing.T) {
	t.Parallel()

	pkt := minecraftHandshakePacket(47, "127.0.0.1", 40000, 2)
	var metadata adapter.InboundContext
	err := sniff.MinecraftHandshake(context.Background(), &metadata, bytes.NewReader(pkt))
	require.NoError(t, err)
	require.Equal(t, C.ProtocolMinecraft, metadata.Protocol)
	require.Empty(t, metadata.Domain)
}

func TestSniffIncompleteMinecraft(t *testing.T) {
	t.Parallel()

	pkt := minecraftHandshakePacket(767, "play.example.com", 25565, 2)
	var metadata adapter.InboundContext
	err := sniff.MinecraftHandshake(context.Background(), &metadata, bytes.NewReader(pkt[:2]))
	require.ErrorIs(t, err, sniff.ErrNeedMoreData)
	require.Empty(t, metadata.Protocol)
}

func TestSniffMinecraftRejectsOtherProtocols(t *testing.T) {
	t.Parallel()

	packets := [][]byte{
		{0x16, 0x03, 0x01, 0x00, 0x05},
		[]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
		{0x03, 0x00, 0x00, 0x13},
		[]byte("SSH-2.0-dropbear\r\n"),
		minecraftHandshakePacket(767, "play.example.com", 0, 2),
		minecraftHandshakePacket(3, "play.example.com", 25565, 2),
		minecraftHandshakePacket(767, "play.example.com", 25565, 4),
		minecraftHandshakePacket(767, "", 25565, 2),
	}
	for _, pkt := range packets {
		var metadata adapter.InboundContext
		err := sniff.MinecraftHandshake(context.Background(), &metadata, bytes.NewReader(pkt))
		require.Error(t, err)
		require.NotErrorIs(t, err, sniff.ErrNeedMoreData)
		require.Empty(t, metadata.Protocol)
	}
}

func TestSniffMinecraftDeclaredLengthHasNoTail(t *testing.T) {
	t.Parallel()

	pkt := minecraftHandshakePacket(767, "play.example.com", 25565, 2)
	require.Less(t, int(pkt[0]), 0x80)
	truncated := append([]byte{pkt[0] + 4}, pkt[1:]...)
	var metadata adapter.InboundContext
	err := sniff.MinecraftHandshake(context.Background(), &metadata, bytes.NewReader(truncated))
	require.Error(t, err)
	require.NotErrorIs(t, err, sniff.ErrNeedMoreData)
	require.Empty(t, metadata.Protocol)
}

func TestSniffMinecraftLengthMismatch(t *testing.T) {
	t.Parallel()

	pkt := minecraftHandshakePacket(767, "play.example.com", 25565, 2)
	padded := append(append([]byte{}, pkt...), 0x00, 0x00, 0x00, 0x00)
	padded[0] = byte(len(padded) - 1)
	var metadata adapter.InboundContext
	err := sniff.MinecraftHandshake(context.Background(), &metadata, bytes.NewReader(padded))
	require.Error(t, err)
	require.NotErrorIs(t, err, sniff.ErrNeedMoreData)
	require.Empty(t, metadata.Protocol)
}

func minecraftHandshakePacket(protocol int, host string, port uint16, state int) []byte {
	payload := appendMinecraftVarInt(nil, 0)
	payload = appendMinecraftVarInt(payload, protocol)
	payload = appendMinecraftVarInt(payload, len(host))
	payload = append(payload, host...)
	payload = append(payload, byte(port>>8), byte(port))
	payload = appendMinecraftVarInt(payload, state)
	return append(appendMinecraftVarInt(nil, len(payload)), payload...)
}

func appendMinecraftVarInt(dst []byte, value int) []byte {
	for value >= 0x80 {
		dst = append(dst, byte(value)|0x80)
		value >>= 7
	}
	return append(dst, byte(value))
}
