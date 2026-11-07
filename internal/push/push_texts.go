package push

import (
	"fmt"
	"strings"
	"time"
)

const maxWhatRunes = 120

type notice struct {
	kind           Kind
	scope          string
	componentID    string
	body           string
	view           string
	title          string
	componentTitle string
}

type texts struct {
	someone       string
	agentSuffix   string
	photo         string
	file          string
	pollClosed    string
	itemsMore     string
	newMember     string
	memberRemoved string
	memberLeft    string
	roleNow       string
	reminder      string
	roleLabels    map[string]string
	clock         func(t time.Time) string
	inMinutes     func(clock string, n int) string
	inHours       func(clock string, n int) string
	inDays        func(clock string, n int) string
	digestTitle   func(total, apps int) string
	digestKinds   map[Kind]string
	digestOther   string
	digestMore    func(n int) string
}

var textsEN = texts{
	someone:       "Someone",
	agentSuffix:   " (agent)",
	photo:         "📷 Photo",
	file:          "File",
	pollClosed:    "Poll closed",
	itemsMore:     "and %d more",
	newMember:     "New member: %s",
	memberRemoved: "Removed: %s",
	memberLeft:    "Left: %s",
	roleNow:       "Your role is now %s",
	reminder:      "Reminder",
	roleLabels:    map[string]string{"owner": "Owner", "admin": "Admin", "member": "Member", "viewer": "Viewer"},
	clock:         func(t time.Time) string { return t.Format("3:04 PM") },
	inMinutes:     func(clock string, n int) string { return fmt.Sprintf("%s, in %d min", clock, n) },
	inHours: func(clock string, n int) string {
		if n == 1 {
			return clock + ", in 1 hour"
		}
		return fmt.Sprintf("%s, in %d hours", clock, n)
	},
	inDays: func(clock string, n int) string {
		if n == 1 {
			return clock + ", in 1 day"
		}
		return fmt.Sprintf("%s, in %d days", clock, n)
	},
	digestTitle: func(total, apps int) string {
		if apps == 1 {
			return fmt.Sprintf("%d new in 1 app", total)
		}
		return fmt.Sprintf("%d new in %d apps", total, apps)
	},
	digestKinds: map[Kind]string{KindChat: "Chat", KindItem: "Items", KindPoll: "Polls", KindFile: "Files", KindMember: "Members", KindReminder: "Reminders"},
	digestOther: "Activity",
	digestMore:  func(n int) string { return fmt.Sprintf("+%d more apps", n) },
}

var textsPL = texts{
	someone:       "Ktoś",
	agentSuffix:   " (agent)",
	photo:         "📷 Zdjęcie",
	file:          "Plik",
	pollClosed:    "Ankieta zamknięta",
	itemsMore:     "i jeszcze %d",
	newMember:     "Nowa osoba: %s",
	memberRemoved: "Usunięto: %s",
	memberLeft:    "Odchodzi: %s",
	roleNow:       "Twoja rola to %s",
	reminder:      "Przypomnienie",
	roleLabels:    map[string]string{"owner": "Właściciel", "admin": "Administrator", "member": "Członek", "viewer": "Obserwator"},
	clock:         func(t time.Time) string { return fmt.Sprintf("%d:%02d", t.Hour(), t.Minute()) },
	inMinutes:     func(clock string, n int) string { return fmt.Sprintf("%s, za %d min", clock, n) },
	inHours: func(clock string, n int) string {
		word := "godzin"
		switch plPlural(n) {
		case "one":
			word = "godzinę"
		case "few":
			word = "godziny"
		}
		return fmt.Sprintf("%s, za %d %s", clock, n, word)
	},
	inDays: func(clock string, n int) string {
		word := "dni"
		if n == 1 {
			word = "dzień"
		}
		return fmt.Sprintf("%s, za %d %s", clock, n, word)
	},
	digestTitle: func(total, apps int) string {
		word := "nowych"
		if plPlural(total) != "many" {
			word = "nowe"
		}
		if apps == 1 {
			return fmt.Sprintf("%d %s w 1 aplikacji", total, word)
		}
		return fmt.Sprintf("%d %s w %d aplikacjach", total, word, apps)
	},
	digestKinds: map[Kind]string{KindChat: "Czat", KindItem: "Pozycje", KindPoll: "Ankiety", KindFile: "Pliki", KindMember: "Osoby", KindReminder: "Przypomnienia"},
	digestOther: "Aktywność",
	digestMore: func(n int) string {
		if n == 1 {
			return "+1 aplikacja więcej"
		}
		return fmt.Sprintf("+%d aplikacji więcej", n)
	},
}

func plPlural(n int) string {
	switch {
	case n == 1:
		return "one"
	case n%10 >= 2 && n%10 <= 4 && (n%100 < 12 || n%100 > 14):
		return "few"
	}
	return "many"
}

func minorUnits(n int64) string {
	sign := ""
	if n < 0 {
		sign, n = "-", -n
	}
	return fmt.Sprintf("%s%d.%02d", sign, n/100, n%100)
}

func textsFor(lang string) texts {
	if lang == "pl" {
		return textsPL
	}
	return textsEN
}

func langOf(locale string) string {
	if locale == "pl" {
		return "pl"
	}
	return "en"
}

func cut(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	r := []rune(s)
	if len(r) <= maxWhatRunes {
		return s
	}
	return string(r[:maxWhatRunes]) + "…"
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

func isEmpty(v any) bool {
	return v == nil || v == ""
}

func (t texts) person(name string, agent bool) string {
	name = strings.TrimSpace(name)
	if name == "" {
		name = t.someone
	}
	if agent {
		name += t.agentSuffix
	}
	return name
}

func (t texts) textByID(id string) (string, bool) {
	switch id {
	case "photo":
		return t.photo, true
	case "file":
		return t.file, true
	case "pollClosed":
		return t.pollClosed, true
	}
	return "", false
}
