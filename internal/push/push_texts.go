package push

import (
	"strings"
)

const maxWhatRunes = 120

type notice struct {
	kind        Kind
	scope       string
	componentID string
	body        string
	view        string
}

type texts struct {
	someone     string
	agentSuffix string
	photo       string
	file        string
	pollClosed  string
	itemsMore   string
	newMember   string
	roleNow     string
	reminder    string
	roleLabels  map[string]string
}

var textsEN = texts{
	someone:     "Someone",
	agentSuffix: " (agent)",
	photo:       "📷 Photo",
	file:        "File",
	pollClosed:  "Poll closed",
	itemsMore:   "and %d more",
	newMember:   "New member: %s",
	roleNow:     "Your role is now: %s",
	reminder:    "Reminder",
	roleLabels:  map[string]string{"owner": "Owner", "admin": "Admin", "member": "Member", "viewer": "Viewer"},
}

var textsPL = texts{
	someone:     "Ktoś",
	agentSuffix: " (agent)",
	photo:       "📷 Zdjęcie",
	file:        "Plik",
	pollClosed:  "Ankieta zamknięta",
	itemsMore:   "i %d innych",
	newMember:   "Nowa osoba: %s",
	roleNow:     "Twoja rola: %s",
	reminder:    "Przypomnienie",
	roleLabels:  map[string]string{"owner": "Właściciel", "admin": "Administrator", "member": "Członek", "viewer": "Obserwator"},
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
