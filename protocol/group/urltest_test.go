package group

import (
	"testing"

	"github.com/sagernet/sing-box/option"

	"github.com/stretchr/testify/require"
)

func TestMedianDelay(t *testing.T) {
	t.Parallel()
	require.Equal(t, uint16(20), medianDelay([]uint16{10, 30, 20}))
	require.Equal(t, uint16(25), medianDelay([]uint16{10, 40}))
	require.Equal(t, uint16(7), medianDelay([]uint16{7}))
}

func TestProbeFailureDoesNotDropLiveScore(t *testing.T) {
	t.Parallel()
	score := &outboundScore{}
	alive, median, died := score.record(80, false, 5, 2)
	require.True(t, alive)
	require.Equal(t, uint16(80), median)
	require.False(t, died)

	alive, median, died = score.record(0, true, 5, 2)
	require.True(t, alive)
	require.Equal(t, uint16(80), median)
	require.False(t, died)
	require.Equal(t, []uint16{80}, score.delays)

	alive, _, died = score.record(0, true, 5, 2)
	require.False(t, alive)
	require.True(t, died)
	require.Empty(t, score.delays)
}

func TestProbeFailureCanSwitchImmediately(t *testing.T) {
	t.Parallel()
	score := &outboundScore{}
	_, _, died := score.record(40, false, 5, 1)
	require.False(t, died)
	alive, _, died := score.record(0, true, 5, 1)
	require.False(t, alive)
	require.True(t, died)
}

func TestFallbackWaitsForConsecutiveFailures(t *testing.T) {
	t.Parallel()
	order := []urlTestView{
		{tag: "de"},
		{tag: "us", alive: true, median: 20},
	}
	choice := chooseURLTest(urlTestModeFallback, order, "de", 100, 3, "", 0)
	require.Equal(t, "de", choice.selected)

	order[0].down = true
	choice = chooseURLTest(urlTestModeFallback, order, "de", 100, 3, "", 0)
	require.Equal(t, "us", choice.selected)

	order[0] = urlTestView{tag: "de", alive: true, median: 200}
	choice = chooseURLTest(urlTestModeFallback, order, "us", 100, 3, "", 0)
	require.Equal(t, "de", choice.selected)
	require.Equal(t, "fallback priority", choice.reason)
}

func TestAutoRequiresConsecutiveFasterMedian(t *testing.T) {
	t.Parallel()
	order := []urlTestView{
		{tag: "de", alive: true, median: 200},
		{tag: "us", alive: true, median: 50},
	}
	choice := chooseURLTest(urlTestModeAuto, order, "de", 100, 3, "", 0)
	require.Equal(t, "de", choice.selected)
	require.Equal(t, 1, choice.streak)

	choice = chooseURLTest(urlTestModeAuto, order, "de", 100, 3, choice.streakTag, choice.streak)
	require.Equal(t, "de", choice.selected)
	require.Equal(t, 2, choice.streak)

	choice = chooseURLTest(urlTestModeAuto, order, "de", 100, 3, choice.streakTag, choice.streak)
	require.Equal(t, "us", choice.selected)
	require.Equal(t, "faster median", choice.reason)
	require.Zero(t, choice.streak)
}

func TestAutoIgnoresJitterInsideTolerance(t *testing.T) {
	t.Parallel()
	order := []urlTestView{
		{tag: "de", alive: true, median: 120},
		{tag: "us", alive: true, median: 80},
	}
	choice := chooseURLTest(urlTestModeAuto, order, "de", 100, 1, "", 0)
	require.Equal(t, "de", choice.selected)
	require.Zero(t, choice.streak)
}

func TestAutoSwitchesImmediatelyWhenCurrentFails(t *testing.T) {
	t.Parallel()
	order := []urlTestView{
		{tag: "de", down: true},
		{tag: "us", alive: true, median: 90},
	}
	choice := chooseURLTest(urlTestModeAuto, order, "de", 100, 3, "us", 2)
	require.Equal(t, "us", choice.selected)
	require.Equal(t, "current outbound failed", choice.reason)
	require.Zero(t, choice.streak)
}

func TestSamplesKeepTheLatestWindow(t *testing.T) {
	t.Parallel()
	score := &outboundScore{}
	for _, delay := range []uint16{10, 20, 30, 40, 50, 60} {
		_, _, died := score.record(delay, false, 5, 2)
		require.False(t, died)
	}
	require.Equal(t, []uint16{20, 30, 40, 50, 60}, score.delays)
	require.Equal(t, uint16(40), score.median())
}

func TestURLTestModeRejectsUnknownValue(t *testing.T) {
	t.Parallel()
	_, err := NewURLTest(t.Context(), nil, nil, "urltest", option.URLTestOutboundOptions{
		Outbounds: []string{"de"},
		Mode:      "sideways",
	})
	require.Error(t, err)
}
