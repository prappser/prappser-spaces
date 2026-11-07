package push

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	webpush "github.com/SherClockHolmes/webpush-go"
)

const digestHour = 19

var digestSendOptions = SendOptions{Urgency: webpush.UrgencyNormal, TTL: 43200, Topic: "digest"}

type digestApp struct {
	ApplicationID string `json:"applicationId"`
	Name          string `json:"name"`
	Count         int    `json:"count"`
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
	parts := make([]string, len(apps))
	for i, a := range apps {
		total += a.Count
		parts[i] = fmt.Sprintf("%s %d", a.Name, a.Count)
	}
	body := strings.Join(parts, ", ")
	if len(apps) == 1 {
		body = apps[0].Name
	}
	return json.Marshal(pushPayload{
		V:     2,
		Kind:  KindDigest,
		Title: textsFor(lang).digestTitle(total, len(apps)),
		Body:  cut(body),
		Tag:   "digest",
		Data:  map[string]any{"digest": digestData{SpaceURL: spaceURL, Apps: apps, Total: total}},
	})
}
