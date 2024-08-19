package types

type PolicyStatus int

const (
	Enabled       PolicyStatus = 0
	Disabled      PolicyStatus = 1
	Preparing     PolicyStatus = 2
	PrepareFailed PolicyStatus = 3
	Failed        PolicyStatus = 4
)
