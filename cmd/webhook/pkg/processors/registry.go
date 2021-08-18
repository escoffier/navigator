package processors

import "reflect"

var ProcessorRegistry = make(map[string]reflect.Type)

func Registry(name string, i interface{}) {
	ProcessorRegistry[name] = reflect.TypeOf(i)
}
