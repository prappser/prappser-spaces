package push

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	webpush "github.com/SherClockHolmes/webpush-go"
)

const digestHour = 19

var digestSendOptions = SendOptions{Urgency: webpush.UrgencyNormal, TTL: 43200, Topic: "digest"}

type digestApp struct {
	ApplicationID string        `json:"applicationId"`
	Name          string        `json:"name"`
	Count         int           `json:"count"`
	Labels        []digestLabel `json:"-"`
}

type digestLabel struct {
	Kind  Kind
	Title string
	Count int
}

const (
	maxDigestLabels = 3
	maxDigestLines  = 3
)

func (t texts) digestLabelText(l digestLabel) string {
	if l.Title != "" {
		return l.Title
	}
	if w, ok := t.digestKinds[l.Kind]; ok {
		return w
	}
	return t.digestOther
}

func (t texts) digestLine(a digestApp) string {
	counts := map[string]int{}
	var order []string
	for _, l := range a.Labels {
		text := t.digestLabelText(l)
		if _, ok := counts[text]; !ok {
			order = append(order, text)
		}
		counts[text] += l.Count
	}
	sort.SliceStable(order, func(i, j int) bool { return counts[order[i]] > counts[order[j]] })
	if len(order) > maxDigestLabels {
		order = order[:maxDigestLabels]
	}
	parts := make([]string, len(order))
	for i, text := range order {
		parts[i] = fmt.Sprintf("%s %d", text, counts[text])
	}
	return a.Name + ": " + strings.Join(parts, ", ")
}

type digestData struct {
	SpaceURL string      `json:"spaceUrl"`
	Apps     []digestApp `json:"apps"`
	Total    int         `json:"total"`
}

func lastDigestAt(now time.Time, loc *time.Location) time.Time {
	d := now.In(loc)
	t := time.Date(d.Year(), d.Month(), d.Day(), digestHour, 0, 0, 0, loc)
	if t.After(now) {
		t = time.Date(d.Year(), d.Month(), d.Day()-1, digestHour, 0, 0, 0, loc)
	}
	return t
}

func digestPayload(lang, spaceURL string, apps []digestApp) ([]byte, error) {
	total := 0
	t := textsFor(lang)
	var lines []string
	for i, a := range apps {
		total += a.Count
		if i < maxDigestLines {
			lines = append(lines, cut(t.digestLine(a)))
		}
	}
	if len(apps) > maxDigestLines {
		lines = append(lines, t.digestMore(len(apps)-maxDigestLines))
	}
	return json.Marshal(pushPayload{
		V:     2,
		Kind:  KindDigest,
		Title: t.digestTitle(total, len(apps)),
		Body:  strings.Join(lines, "\n"),
		Tag:   "digest",
		Data:  map[string]any{"digest": digestData{SpaceURL: spaceURL, Apps: apps, Total: total}},
	})
}
