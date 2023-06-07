package dequeuers

type DequeueType string

const (
	TypeNodeImageTask     DequeueType = "node-image"
	TypeRegistryImageTask DequeueType = "registry-image"
)
