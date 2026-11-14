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

func TestSniffTerrariaConnect(t *testing.T) {
	t.Parallel()

	pkt := terrariaConnectPacket("Terraria279")
	var metadata adapter.InboundContext
	err := sniff.TerrariaConnect(context.Background(), &metadata, bytes.NewReader(append(pkt, 0x04, 0x00)))
	require.NoError(t, err)
	require.Equal(t, C.ProtocolTerraria, metadata.Protocol)
	require.Equal(t, "Terraria279", metadata.Client)
	require.Empty(t, metadata.Domain)
}

func TestSniffTerrariaOlderRelease(t *testing.T) {
	t.Parallel()

	pkt := terrariaConnectPacket("Terraria194")
	var metadata adapter.InboundContext
	err := sniff.TerrariaConnect(context.Background(), &metadata, bytes.NewReader(pkt))
	require.NoError(t, err)
	require.Equal(t, C.ProtocolTerraria, metadata.Protocol)
	require.Equal(t, "Terraria194", metadata.Client)
}

func TestSniffIncompleteTerraria(t *testing.T) {
	t.Parallel()

	pkt := terrariaConnectPacket("Terraria279")
	var metadata adapter.InboundContext
	err := sniff.TerrariaConnect(context.Background(), &metadata, bytes.NewReader(pkt[:2]))
	require.ErrorIs(t, err, sniff.ErrNeedMoreData)
	require.Empty(t, metadata.Protocol)
}

func TestSniffTerrariaRejectsOtherProtocols(t *testing.T) {
	t.Parallel()

	packets := [][]byte{
		{0x16, 0x03, 0x01, 0x00, 0x05},
		[]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
		[]byte("SSH-2.0-dropbear\r\n"),
		{0x03, 0x00, 0x00, 0x13},
		terrariaConnectPacket("Minecraft279"),
		terrariaConnectPacket("Terraria"),
		terrariaConnectPacket("Terraria279a"),
		{0x0f, 0x00, 0x02, 0x0b, 'T', 'e', 'r', 'r', 'a', 'r', 'i', 'a', '2', '7', '9'},
	}
	for _, pkt := range packets {
		var metadata adapter.InboundContext
		err := sniff.TerrariaConnect(context.Background(), &metadata, bytes.NewReader(pkt))
		require.Error(t, err)
		require.NotErrorIs(t, err, sniff.ErrNeedMoreData)
		require.Empty(t, metadata.Protocol)
	}
}

func terrariaConnectPacket(version string) []byte {
	payload := []byte{1, byte(len(version))}
	payload = append(payload, version...)
	total := len(payload) + 2
	return append([]byte{byte(total), byte(total >> 8)}, payload...)
}
