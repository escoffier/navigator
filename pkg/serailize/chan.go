package serailize

type Serializer struct {
	ch chan struct{}
}

func NewSerializer() Serializer {
	return Serializer{
		ch: make(chan struct{}, 1),
	}
}

func (s *Serializer) Obtain() chan<- struct{} {
	return s.ch
}

func (s *Serializer) Release() {
	<-s.ch
}
