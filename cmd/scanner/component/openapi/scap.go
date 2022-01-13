package openapi

import "context"

type ScapService struct{}

func (s *ScapService) CreateTasks(ctx context.Context) {}
func (s *ScapService) Results(ctx context.Context)     {}
func (s *ScapService) Tasks(ctx context.Context)       {}
func (s *ScapService) Detail(ctx context.Context)      {}
