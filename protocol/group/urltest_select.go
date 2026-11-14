package group

import "slices"

const (
	urlTestModeAuto           = "auto"
	urlTestModeFallback       = "fallback"
	defaultURLTestSamples     = 5
	defaultURLTestConsecutive = 3
	defaultURLTestMaxFailures = 2
)

type urlTestProbe struct {
	tag   string
	delay uint16
	err   error
}

type outboundScore struct {
	delays   []uint16
	failures int
	alive    bool

	pending        bool
	pendingAlive   bool
	pendingDied    bool
	pendingSuccess bool
	pendingMedian  uint16
}

func (s *outboundScore) record(delay uint16, failed bool, samples, maxFailures int) (alive bool, median uint16, died bool) {
	if failed {
		s.failures++
		if s.failures >= maxFailures {
			died = s.alive || len(s.delays) > 0
			s.alive = false
			s.delays = nil
			return false, 0, died
		}
		if s.alive {
			return true, medianDelay(s.delays), false
		}
		return false, 0, false
	}
	s.failures = 0
	s.alive = true
	s.delays = append(s.delays, delay)
	if samples > 0 && len(s.delays) > samples {
		s.delays = append([]uint16(nil), s.delays[len(s.delays)-samples:]...)
	}
	return true, medianDelay(s.delays), false
}

func (s *outboundScore) median() uint16 {
	return medianDelay(s.delays)
}

func medianDelay(values []uint16) uint16 {
	if len(values) == 0 {
		return 0
	}
	sorted := append([]uint16(nil), values...)
	slices.Sort(sorted)
	mid := len(sorted) / 2
	if len(sorted)%2 == 1 {
		return sorted[mid]
	}
	return uint16((uint32(sorted[mid-1]) + uint32(sorted[mid])) / 2)
}

type urlTestView struct {
	tag    string
	alive  bool
	down   bool
	median uint16
}

type urlTestChoice struct {
	selected  string
	reason    string
	streakTag string
	streak    int
}

func chooseURLTest(mode string, order []urlTestView, current string, tolerance uint16, consecutive int, streakTag string, streak int) urlTestChoice {
	if consecutive < 1 {
		consecutive = 1
	}
	alive := func(tag string) (uint16, bool) {
		for _, item := range order {
			if item.tag == tag && item.alive {
				return item.median, true
			}
		}
		return 0, false
	}
	bestAlive := func() (string, bool) {
		found := false
		var selected string
		var median uint16
		for _, item := range order {
			if !item.alive {
				continue
			}
			if !found || item.median < median {
				selected = item.tag
				median = item.median
				found = true
			}
		}
		return selected, found
	}
	if len(order) == 0 {
		return urlTestChoice{}
	}
	if mode == urlTestModeFallback {
		for _, item := range order {
			if item.alive {
				reason := "fallback priority"
				if current == "" {
					reason = "initial selection"
				}
				if item.tag == current {
					reason = ""
				}
				return urlTestChoice{selected: item.tag, reason: reason}
			}
			if item.tag == current && !item.down {
				return urlTestChoice{selected: current}
			}
		}
		if current != "" {
			return urlTestChoice{selected: current}
		}
		return urlTestChoice{selected: order[0].tag, reason: "initial selection"}
	}

	currentMedian, currentAlive := alive(current)
	currentDown := false
	for _, item := range order {
		if item.tag == current {
			currentDown = item.down
			break
		}
	}
	if current != "" && !currentDown {
		if !currentAlive {
			return urlTestChoice{selected: current}
		}
	} else {
		if tag, ok := bestAlive(); ok {
			reason := "initial selection"
			if current != "" {
				reason = "current outbound failed"
			}
			return urlTestChoice{selected: tag, reason: reason}
		}
		if current != "" {
			return urlTestChoice{selected: current}
		}
		return urlTestChoice{selected: order[0].tag, reason: "initial selection"}
	}

	found := false
	var challenger string
	var challengerMedian uint16
	for _, item := range order {
		if !item.alive || item.tag == current {
			continue
		}
		if uint32(currentMedian) > uint32(item.median)+uint32(tolerance) {
			if !found || item.median < challengerMedian {
				challenger = item.tag
				challengerMedian = item.median
				found = true
			}
		}
	}
	if !found {
		return urlTestChoice{selected: current}
	}
	nextStreak := 1
	if streakTag == challenger {
		nextStreak = streak + 1
	}
	if nextStreak >= consecutive {
		return urlTestChoice{selected: challenger, reason: "faster median"}
	}
	return urlTestChoice{selected: current, streakTag: challenger, streak: nextStreak}
}
