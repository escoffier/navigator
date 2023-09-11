package iac

import (
	"context"
	iacModel "gitlab.com/piccolo_su/vegeta/pkg/model/iac"
	"gitlab.com/security-rd/go-pkg/logging"
	"gorm.io/gorm"
	"time"
)

func NewDockerfile(rdb *gorm.DB) error {
	timeOutCtx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	// template
	templates, err := iacModel.FindDockerfileTemplates(timeOutCtx, db, map[string]interface{}{"builtin": 1})
	if err != nil {
		logging.Get().Error().Err(err).Msg("find builtin template fails")
		return err
	}
	if len(templates) == 0 {
		rules, err := iacModel.FindDockerfileRules(timeOutCtx, db, map[string]interface{}{}, map[string]interface{}{})
		if err != nil {
			logging.Get().Error().Err(err).Msgf("FindDockerfileRules fails")
			return err
		}
		if len(rules) == 0 {
			rules = iacModel.DockerfileRules
			err = iacModel.CreateDockerfileRules(timeOutCtx, rdb, rules)
			if err != nil {
				logging.Get().Error().Err(err).Msgf("CreateDockerfileRules fails")
				return err
			}
		}
		ruleBuiltinIDs := make([]string, len(rules))
		for i := range rules {
			ruleBuiltinIDs[i] = rules[i].BuiltinID
		}
		template, err := iacModel.CreateDockerfileTemplate(timeOutCtx, db, iacModel.DockerfileTemplate{
			Name:        DefaultTemplateName,
			Description: "",
			Rules:       ruleBuiltinIDs,
			Creator:     "",
			Updater:     "",
			Builtin:     true,
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		})
		if err != nil {
			logging.Get().Error().Err(err).Msgf("CreateDockerfileTemplate fails")
			return err
		}
		_, err = iacModel.CreateDockerfileTemplateSnapshot(timeOutCtx, db, iacModel.DockerfileTemplateSnapshot{
			TemplateID:  template.ID,
			Name:        DefaultTemplateName,
			Description: "",
			Rules:       ruleBuiltinIDs,
			Creator:     "",
			Updater:     "",
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		})
		if err != nil {
			logging.Get().Err(err).
				Int("id", template.ID).Msgf("CreateDockerfileTemplateSnapshot fails")
			return err
		}
	}
	
	return nil
}
