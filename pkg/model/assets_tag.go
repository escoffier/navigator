package model

import (
	"time"
)

type TagRelObjType string

const (
	ObjType_cluster   TagRelObjType = "cluster"
	ObjType_namespace TagRelObjType = "namespace"
	ObjType_resource  TagRelObjType = "resource"
	ObjType_pod       TagRelObjType = "pod"
	ObjType_container TagRelObjType = "container"
	ObjType_service   TagRelObjType = "service"
	ObjType_endpoints TagRelObjType = "endpoints"
	ObjType_ingress   TagRelObjType = "ingress"
	ObjType_api       TagRelObjType = "api"
	ObjType_secret    TagRelObjType = "secret"
	ObjType_pv        TagRelObjType = "pv"
	ObjType_pvc       TagRelObjType = "pvc"
	ObjType_node      TagRelObjType = "node"
	ObjType_webSit    TagRelObjType = "webSit"
	ObjType_app       TagRelObjType = "app"
	ObjType_webApp    TagRelObjType = "webApp"
	ObjType_dbApp     TagRelObjType = "dbApp"
	ObjType_label     TagRelObjType = "label"
)

var TagRelObjList = []TagRelObjType{ObjType_cluster, ObjType_namespace, ObjType_resource, ObjType_pod, ObjType_container, ObjType_service, ObjType_endpoints, ObjType_ingress,
	ObjType_api, ObjType_secret, ObjType_pv, ObjType_pvc, ObjType_label, ObjType_node, ObjType_webSit, ObjType_app, ObjType_webApp, ObjType_dbApp}

type TensorAssetsTag struct {
	ID        string    `gorm:"column:id;type:bigint;primaryKey" json:"id,omitempty"`
	CreatedAt time.Time `gorm:"column:created_at" json:"createdAt,omitempty"`
	UpdatedAt time.Time `gorm:"column:updated_at" json:"updatedAt,omitempty"`
	Status    int32     `gorm:"column:status;type:smallint" json:"status"`
	Name      string    `json:"name" gorm:"column:name"`
	Desc      string    `json:"desc" gorm:"column:desc"`
	Type      int       `json:"type" gorm:"column:type"`
}

func (rc TensorAssetsTag) TableName() string {
	return "ivan_assets_tag"
}

type TensorAssetsTagRel struct {
	TableBase               // id: cluster_key/namespace/kind/resource_name
	TagId     string        `json:"tagId" gorm:"column:tag_id"`
	ObjType   TagRelObjType `json:"objType" gorm:"column:obj_type"`
	ObjId     string        `json:"ObjId" gorm:"column:obj_id"`
}

func (rc TensorAssetsTagRel) TableName() string {
	return "ivan_assets_tag_rel"
}
