//go:build with_acme

package acme

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestChallengeListenHost(t *testing.T) {
	t.Parallel()
	require.Equal(t, "58.23.204.55", challengeListenHost("58.23.204.55"))
	require.Equal(t, "2408:8649:5500:1a55::", challengeListenHost("2408:8649:5500:1a55::"))
	require.Equal(t, "", challengeListenHost("example.com"))
	require.Equal(t, net.JoinHostPort("2408:8649:5500:1a55::", "80"), net.JoinHostPort(challengeListenHost("2408:8649:5500:1a55::"), "80"))
}
