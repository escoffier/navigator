package ci

import (
	"context"
	"encoding/json"
	"os"
	"strings"

	"gitlab.com/security-rd/go-pkg/logging"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store"
	scanner_ci "gitlab.com/piccolo_su/vegeta/pkg/model/scanner-ci"
)

type PolicyManager struct {
	dal store.ScanCiInterface
}

func NewPolicyManager(dal store.ScanCiInterface) PolicyManager {
	return PolicyManager{dal: dal}
}

func (p *PolicyManager) GetPolicyList(ctx context.Context, limit int64, offset int64, name string) ([]scanner_ci.CiPolicy, int64, error) {
	return p.dal.GetPolicyList(ctx, limit, offset, name)
}

func (p *PolicyManager) CreatePolicy(ctx context.Context, data *scanner_ci.CiPolicy) (int64, error) {
	return p.dal.CreatePolicy(ctx, *data)
}

func (p *PolicyManager) UpdatePolicy(ctx context.Context, data *scanner_ci.CiPolicy) error {
	return p.dal.UpdatePolicy(ctx, *data)
}

func (p *PolicyManager) GetPolicyDetail(ctx context.Context, id int64) (scanner_ci.CiPolicy, error) {
	return p.dal.GetPolicyDetail(ctx, id)
}

func (p *PolicyManager) DeleteCiPolicy(ctx context.Context, id int64) error {
	return p.dal.DeletePolicy(ctx, id)
}

// GetPolicyByName get policy from db and wrap to ci-agent
func (p *PolicyManager) GetPolicyByName(ctx context.Context, name string) (scanner_ci.Policy, error) {
	// get policy
	ciPolicy, err := p.dal.GetPolicyByName(context.Background(), name)
	if err != nil {
		logging.Get().Err(err).Str("policyName", name).Msg("get policy failed")
		return scanner_ci.Policy{}, err
	}

	// get image whitelist
	imageWhiteList, _, err := p.dal.GetWhitelist(context.Background(), scanner_ci.WhitelistParams{})
	if err != nil {
		logging.Get().Err(err).Str("policyName", name).Msg("get image white list failed")
		return scanner_ci.Policy{}, err
	}

	// transform
	policy, err := p.TransFormPolicy(ciPolicy, imageWhiteList)
	if err != nil {
		logging.Get().Err(err).Str("policyName", name).Msg("transform policy failed")
		return scanner_ci.Policy{}, err
	}

	return policy, nil
}

func (p *PolicyManager) TransFormPolicy(ciPolicy scanner_ci.CiPolicy, imageWhiteList []scanner_ci.CiWhitelist) (scanner_ci.Policy, error) {
	// make image whitelist for ci tool
	iw := make([]scanner_ci.ImageNamePattern, 0)
	for _, v := range imageWhiteList {
		tmp := scanner_ci.ImageNamePattern{
			Value:   v.Name,
			EndTime: v.ExpireTime,
		}
		iw = append(iw, tmp)
	}

	// transform sensitive file rule for ci tool
	sr := make([]scanner_ci.Pattern, 0)
	tmpArr := strings.Split(ciPolicy.SensitiveFilePolicy, ",")
	for _, v := range tmpArr {
		pt := scanner_ci.Pattern{
			SecretType: "FileExt",
			Value:      v,
		}
		sr = append(sr, pt)
	}

	// vuln whitelist for ci tool
	vw := strings.Split(ciPolicy.VulnWhitelist, ",")
	vb := strings.Split(ciPolicy.VulnPolicy, ",")

	// transform
	policy := scanner_ci.Policy{}
	policy.Name = ciPolicy.Name
	policy.Vuln.Enabled = ciPolicy.VulnEnable
	policy.Vuln.Severity = ciPolicy.VulnLevel
	policy.Vuln.BlackListVulns = vb
	policy.Vuln.WhiteListVulns = vw
	policy.Vuln.IgnoreUnfixed = ciPolicy.IgnoreIrreparable
	policy.Vuln.Action = ciPolicy.VulnRuleMode
	policy.Vuln.ActionCode = ActionNameToCode(ciPolicy.VulnRuleMode)
	policy.ImageNameWhiteLists = iw
	policy.SensitiveFile.Enabled = ciPolicy.SensitiveEnable
	policy.SensitiveFile.Ext = sr
	policy.SensitiveFile.Action = ciPolicy.SensitiveRuleMode
	policy.SensitiveFile.ActionCode = ActionNameToCode(ciPolicy.SensitiveRuleMode)

	files, err := os.ReadFile("/configs/scanner/patterns.json")
	if err != nil {
		logging.Get().Warn().Err(err).Msg("read default pattern error")
	} else {
		err = json.Unmarshal(files, &policy.SensitiveFile.DefaultFilePattern)
		if err != nil {
			logging.Get().Warn().Err(err).Msg("unmarshal pattern error")
		}
	}

	return policy, nil
}

func (p *PolicyManager) GetPolicies(ctx context.Context) ([]scanner_ci.Policy, error) {
	// get all policies
	ciPolicies, _, err := p.dal.GetPolicyList(ctx, 0, 0, "")
	if err != nil {
		logging.Get().Err(err).Msg("get policies failed")
		return nil, err
	}

	// get image whitelist
	imageWhiteList, _, err := p.dal.GetWhitelist(context.Background(), scanner_ci.WhitelistParams{})
	if err != nil {
		logging.Get().Err(err).Msg("get image white list failed")
		return nil, err
	}

	// transform all
	policies := make([]scanner_ci.Policy, 0)
	for _, v := range ciPolicies {
		tmp, err := p.TransFormPolicy(v, imageWhiteList)
		if err != nil {
			// just log,continue
			logging.Get().Err(err).Str("dbPolicy", v.Name).Msg("transform policy failed,ignored")
		}
		policies = append(policies, tmp)
	}
	return policies, nil
}

func ActionNameToCode(action string) int {
	switch action {
	case scanner_ci.CiActionBlock:
		return scanner_ci.CiPolicyResultCodeBlock
	case scanner_ci.CiActionAlert:
		return scanner_ci.CiPolicyResultCodeAlert
	case scanner_ci.CiActionPass:
		return scanner_ci.CiPolicyResultCodePass
	default:
		return scanner_ci.CiPolicyResultCodeUnknown
	}
}
