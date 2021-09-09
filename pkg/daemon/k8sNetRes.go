package daemon

type K8sResData struct {
	Cluster   string `json:"cluster" gorm:"primaryKey;type:varchar(100)"`
	Name      string `json:"name" gorm:"primaryKey;type:varchar(100)"`
	Kind      string `json:"kind" gorm:"primaryKey;type:varchar(100)"`
	Namespace string `json:"namespace" gorm:"primaryKey;type:varchar(100)"`
}
