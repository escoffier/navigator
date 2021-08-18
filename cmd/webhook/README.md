# tensor-webhook

集成了所有webhook功能，每个功能在单独的包里面实现具体的业务逻辑。

## 框架实现简介
webhook框架基于责任链模式（Chain of Responsibility）实现。根据功能分为两个责任链：  

* validation链，负责处理api server的验证准入请求。
* mutation链，负责处理api server的修改准入请求。

api server的webhook请求中，携带有希望验证或者的修改的k8s资源信息，对于每种k8s资源，定义了资源验证接口和修改接口，例如对于Pod：  

```
type PodMutator interface {
	Name() string
	Init()
	Mutate(pod *core.Pod)
}

type PodValidator interface {
    Validate(pod *core.Pod, parameters *ValidatingParameters) error
    PreValidate(pod *core.Pod, parameters *ValidatingParameters) bool
    Name() string
    Init()
}
```

## webhook处理模块开发
### 模块开发流程
webhook处理模块需要实现对应的资源处理接口（xxxValidator或者xxxMutator）。比如要验证pod资源，需要实现PodValidator接口。   
接口中每个方法负责不同的功能：
* PreValidate  预处理，比如实现对资源的帅选。
* Validate   实现具体的验证处理。
* Init  初始化，比如配置参数的加载。每个处理模块的参数由模块自己负责加载，建议使用configmap或者环境变量，这样可以保证每个处理模块的相对独立性。
* Name  名称，webhook框架根据名称创建对应的处理对象。

### 处理模块注册
每个模块要生效，需要将自身添加到调用链中。
1. 在模块中实现一个Register方法：  
````   
func Register()  {
   imageValidator := ImageValidator{}
   processors.Registry(imageValidator.Name(), imageValidator)
}
   ````
2. 在webhook.go的init方法中调用Register，将自身类型注册到全局的类型注册表中，注册表中保存了处理器的名称和对应的类型。 
````   
func init() {
   // register all processors here
   imagevalidator.Register()
}
````

3. webhook处理模块由配置参数决定是否启动: --validators=image-validator，框架将会根据validator的名称，在类型注册表中找到对应的处理器类型，自动创建处理器对象，并加入到validation链中。