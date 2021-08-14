package networktopo

type ResourceInfo struct {
	Cluster   string
	Namespace string
	Kind      string
	Resource  string
	Port      int
	Protocol  string
}
