package push

import (
	"encoding/json"
	"testing"

	"github.com/prappser/prappser-spaces/internal/user"
	"github.com/stretchr/testify/assert"
)

func TestPushService_Fanout_ShouldNotifyExpensesV2AudienceFromRealSchema(t *testing.T) {
	const (
		eKey = "e_0b7e5c1a-3f2d-4a9e-8c11-5d6e7f8a9b0c"
		sKey = "s_0b7e5c1a-3f2d-4a9e-8c11-5d6e7f8a9b0c"
		rKey = "r_pk-creditor__pk-debtor"
		pKey = "pay_pk-a"
	)
	members := []string{"a", "payer", "other"}
	cases := []struct {
		name     string
		key      string
		oldV     any
		newV     any
		wantSubs []string
		wantBody string
	}{
		{"expense notifies the named members only", eKey, nil, `{"what":"Dinner","amount":4500,"notify":["pk-a","pk-payer"]}`, []string{"sub-a", "sub-payer"}, "Ann: Dinner · 45.00"},
		{"expense without notify reaches every member", eKey, nil, `{"what":"Dinner","amount":4500}`, []string{"sub-a", "sub-payer", "sub-other"}, "Ann: Dinner · 45.00"},
		// pins fail-open on malformed data on purpose
		{"expense notify as a number falls back to every member", eKey, nil, `{"what":"Dinner","amount":4500,"notify":7}`, []string{"sub-a", "sub-payer", "sub-other"}, "Ann: Dinner · 45.00"},
		{"expense notify drops a non-member", eKey, nil, `{"what":"Dinner","amount":4500,"notify":["pk-a","pk-stranger"]}`, []string{"sub-a"}, "Ann: Dinner · 45.00"},
		{"expense notify naming only a non-member pushes nobody", eKey, nil, `{"what":"Dinner","amount":4500,"notify":"pk-stranger"}`, nil, ""},
		{"settlement notifies the other party with the note", sKey, nil, `{"from":"pk-a","to":"pk-payer","amount":2000,"notify":"pk-payer","note":"paid back 20.00"}`, []string{"sub-payer"}, "Ann: paid back 20.00"},
		{"settlement without a note pushes nobody", sKey, nil, `{"from":"pk-a","to":"pk-payer","amount":2000,"notify":"pk-payer"}`, nil, ""},
		{"first reminder notifies only the debtor", rKey, nil, `{"from":"pk-a","to":"pk-payer","amount":2000,"at":1,"note":"pay back"}`, []string{"sub-payer"}, "Ann: pay back"},
		{"resend with a new at notifies the debtor again", rKey, `{"from":"pk-a","to":"pk-payer","amount":2000,"at":1,"note":"pay back"}`, `{"from":"pk-a","to":"pk-payer","amount":2000,"at":2,"note":"pay back"}`, []string{"sub-payer"}, "Ann: pay back"},
		{"resend with identical content does not fire", rKey, `{"from":"pk-a","to":"pk-payer","amount":2000,"at":1,"note":"pay back"}`, `{"from":"pk-a","to":"pk-payer","amount":2000,"at":1,"note":"pay back"}`, nil, ""},
		{"reminder tombstone does not fire", rKey, `{"from":"pk-a","to":"pk-payer","amount":2000,"at":1,"note":"pay back"}`, "", nil, ""},
		{"payment methods array does not fire", pKey, nil, []any{map[string]any{"id": "m1", "type": "blik", "value": "600123456"}}, nil, ""},
		{"payment methods clear does not fire", pKey, []any{map[string]any{"id": "m1", "type": "blik", "value": "600123456"}}, "", nil, ""},
	}
	for _, c := range cases {
		// given
		repo := newMockPushRepository()
		sender := newMockWebpushSender(SendResult{StatusCode: 201})
		svc := newGoldenService(repo, sender)
		recipients := make([]string, len(members))
		for i, id := range members {
			recipients[i] = "pk-" + id
		}
		for _, id := range append(members, "stranger") {
			repo.subscriptions["sub-"+id] = &Subscription{ID: "sub-" + id, DevicePublicKey: "pk-" + id, NotifyMode: user.NotifyModeAll, MutedApplicationIDs: []string{}}
		}

		// when
		svc.fanout(gComp("expenses-2", gChange(c.key, c.oldV, c.newV)), goldenApp(), "Ann", false, recipients)

		// then
		var gotSubs, gotBodies []string
		for _, call := range sender.calls {
			var decoded map[string]any
			assert.NoError(t, json.Unmarshal(call.payload, &decoded), c.name)
			gotSubs = append(gotSubs, call.sub.ID)
			gotBodies = append(gotBodies, decoded["body"].(string))
		}
		assert.ElementsMatch(t, c.wantSubs, gotSubs, c.name)
		for _, b := range gotBodies {
			assert.Equal(t, c.wantBody, b, c.name)
		}
	}
}
