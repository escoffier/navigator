How to Create a Service
=========
1. create a directory in the service directory of the corresponding cmd directories.
2. Use Singleton Pattern for creation and getting.
3. Please try your best to obey the following examples:    
  
```go
var (
    instance *YourStructName
    once sync.Once
)

func Init(dependencies... interface{}) error {
    // argument check
    once.Do(func() {
        // init
        instance = newYourStruct(dependencies...)
    })
    return nil
}

func Get() (*YourStructName, bool) {
    return instance, instance != nil
}
```
4. Call Init when the service starts and maybe panic if having errors creating it.