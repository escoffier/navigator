package api

import (
	"math/rand"
	"net/http"
	"time"

	"github.com/go-chi/chi"

	"gitlab.com/piccolo_su/vegeta/pkg/response"
)

type profilesPoliceItemData struct {
	Key       int       `json:"key"`
	ID        string    `json:"id"`
	Owner     string    `json:"owner"`
	OwnerID   string    `json:"ownerId"`
	Category  string    `json:"category"`
	Name      string    `json:"name"`
	UpdatedAt time.Time `json:"updatedAt"`
	CreatedAt time.Time `json:"createdAt"`
	Node      string    `json:"node"`
	Triggers  int       `json:"triggers"`
	Level     string    `json:"level"`
	Entities  []string  `json:"entities"`
}

//type profilesRuleItemData struct {
//}

type profilesPolicies []profilesPoliceItemData

type profilesRules struct {
}

func (api *api) restProfiles() func(chi.Router) {
	return func(r chi.Router) {
		r.Get("/policies", policiesProfiles)
		r.Get("/rules", rulesProfiles)
	}
}

// @Summary Profiles Policies API
// @Description Get all policies
// @ID v1-profiles-policies
// @Produce json
// @Success 200 {object} api.profilesPolicies "Profile Policies Data"
// @Router /api/v1/profiles/policies [get]
func policiesProfiles(w http.ResponseWriter, r *http.Request) {
	d := profilesPolicies{
		{1, "Policy-1", "老板",
			"00000001", "host",
			"策略1", time.Now(), time.Now(),
			"1", rand.Intn(20) + 5, "high", []string{},
		},
		{2, "Policy-2", "管理员",
			"00000002", "monitor",
			"策略1", time.Now(), time.Now(),
			"1", rand.Intn(20) + 5, "medium", []string{},
		},
		{3, "Policy-3", "周润发",
			"00000003", "dpi",
			"策略1", time.Now(), time.Now(),
			"1", rand.Intn(20) + 5, "low", []string{},
		},
		{4, "Policy-4", "周星星",
			"00000004", "image",
			"策略1", time.Now(), time.Now(),
			"1", rand.Intn(20) + 5, "medium", []string{},
		},
		{5, "Policy-5", "老板",
			"00000001", "scap",
			"策略1", time.Now(), time.Now(),
			"1", rand.Intn(20) + 5, "low", []string{},
		},
	}

	response.Ok(w, d)
}

// @Summary Profiles Rules API
// @Description Get all rules
// @ID v1-profiles-rules
// @Produce json
// @Success 200 {object} api.profilesRules "Profile Rules Data"
// @Router /api/v1/profiles/rules [get]
func rulesProfiles(w http.ResponseWriter, r *http.Request) {
	d := profilesRules{}
	response.Ok(w, d)
}
