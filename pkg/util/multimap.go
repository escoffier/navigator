package util

// Multimap is a map with a slice of objects as values. It's concurrently unsafe
type Multimap map[string][]interface{}

func (m Multimap) Put(key string, values ...interface{}) {
	vslice, exist := m[key]
	if !exist {
		vslice = make([]interface{}, 0, 3)
	}

	vslice = append(vslice, values...)

	m[key] = vslice
}

func (m Multimap) Get(key string) []interface{} {
	vslice, exist := m[key]
	if !exist {
		return nil
	}
	return vslice
}

func (m Multimap) ContainsKey(key string) bool {
	_, exist := m[key]
	return exist
}

type CompareFunc func(obj0, obj1 interface{}) int // return 0 to be equal

func (m Multimap) Contains(key string, val interface{}, comp CompareFunc) bool {
	vslice, exist := m[key]
	if !exist {
		return false
	}
	for _, sliceVal := range vslice {
		if comp(val, sliceVal) == 0 {
			return true
		}
	}
	return false
}
