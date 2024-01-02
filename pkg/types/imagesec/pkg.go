package imagesec

type Package struct {
	Name       string   `json:"name"`       // 软件包名称，如libgcc
	Version    string   `json:"version"`    // 软件包版本，如1.0.0-ubuntu18
	SrcName    string   `json:"srcName"`    // 源包名称，如gcc
	SrcVersion string   `json:"srcVersion"` // 源包版本，如1.0.0
	License    string   `json:"license"`    // 开源协议，如MIT
	DependsOn  []string `json:"dependsOn"`  // 依赖的软件包，如 gccbase@1.0.0,gccbin@1.0.0
	FilePath   string   `json:"filePath"`   // Each package metadata have the file path, while the package from lock files does not have.e.g./root/spring_boot.jar
	Layer      string   `json:"layer"`      // 所属layer的digest
}

type License struct {
	Name     string `json:"name"`
	Layer    string `json:"layer"` // 所属layer的digest
	Filename string `json:"filename"`
	MD5      string `json:"md5"`
	Content  []byte `json:"content"`
}
