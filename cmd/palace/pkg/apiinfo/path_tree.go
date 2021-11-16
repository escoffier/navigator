package apiinfo

type PathTree struct {
}

type node struct {
	children []*node
	value    string
}
