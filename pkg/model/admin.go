package model

import (
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

const (
	UserCollection           = "rbac_user"
	RoleCollection           = "rbac_role"
	AccessCollection         = "rbac_access"
	RelaUserRoleCollection   = "rbac_rela_user_role"
	RelaRoleAccessCollection = "rbac_rela_role_access"

	IdxUser     = "user_name"
	IdxRole     = "role_name"
	IdxAccess   = "access_name"
	IdxRelaUR_1 = "user_name"
	IdxRelaUR_2 = "role_name"
	IdxRelaRA_1 = "role_name"
	IdxRelaRA_2 = "access_name"
)

const (
	DEFAULT_SUPER_ADMIN_USER = "SuperAdminUser"

	ROLE_SUPERADMIN = "super-admin"
	ROLE_ADMIN      = "admin"
	ROLE_HIGHLEVEL  = "high-level"
	ROLE_NORMAL     = "normal"
	ROLE_VISITOR    = "visitor"

	ACCESS_COMPLIANCE         = "compliance"
	ACCESS_SETTING            = "setting"
	ACCESS_RUNTIME_DETECTION  = "runtime-detection"
	ACCESS_IMAGE_VULNERBILTY  = "image-vulnerability"
	ACCESS_ONLINE_VULNERBILTY = "online-vulnerability"
	ACCESS_ALERTS             = "alerts"
	ACCESS_AUDIT              = "audit"
	ACCESS_CLEANUP            = "cleanup"
	ACCESS_SUPER_ADMIN        = "super-admin"
	ACCESS_MICROSERVICE       = "microservice"

	ACCESS_COMPLIANCE_ZH         = "安全合规"
	ACCESS_SETTING_ZH            = "设置"
	ACCESS_RUNTIME_DETECTION_ZH  = "运行检测"
	ACCESS_IMAGE_VULNERBILTY_ZH  = "镜像脆弱性"
	ACCESS_ONLINE_VULNERBILTY_ZH = "在线漏洞"
	ACCESS_ALERTS_ZH             = "报警"
	ACCESS_AUDIT_ZH              = "审查"
	ACCESS_CLEANUP_ZH            = "清理"
	ACCESS_SUPER_ADMIN_ZH        = "超级管理员"
	ACCESS_MICROSERVICE_ZH       = "微服务安全"

	URL_SETTING            = "/api/v1/config"
	URL_IMAGE_VULNERBILTY  = "/api/v1/scanner"
	URL_COMPLIANCE         = "/api/v1/scap"
	URL_ONLINE_VULNERBILTY = "/api/v1/onlineVulnerabilities"
	URL_RUNTIME_DETECTION  = "/api/v1/runtimeDetectionConfig"
	URL_ALERTS             = "/api/v1/alerts"
	URL_AUDIT              = "/api/v1/audit"
	URL_CLEANUP            = "/api/v1/cleanup"
	URL_SUPER_ADMIN        = "/api/v1/superAdmin"
	URL_MICROSERVICE       = "/api/v1/microservice"

	IGNORE_ACCESS_URL_AUTH    = "/api/v1/auth"
	IGNORE_ACCESS_URL_USER    = "/api/v1/user"
	IGNORE_ACCESS_URL_PING    = "/ping"
	IGNORE_ACCESS_URL_SWAGGER = "/swagger"
	IGNORE_ACCESS_URL_HARBOR  = "/harbor"
)

type User struct {
	ID           primitive.ObjectID `json:"id" bson:"_id"`
	UserName     string             `json:"userName" bson:"user_name"` // index
	Pwd          string             `json:"pwd" bson:"pwd"`
	Title        string             `json:"title" bson:"title"`
	Name         string             `json:"name" bson:"name"`
	Email        string             `json:"email" bson:"email"`
	Group        string             `json:"group" bson:"group"`
	Avatar       string             `json:"avatar" bson:"avatar"`
	RoleNameList []string           `json:"roleNameList"`
}

type Role struct {
	ID             primitive.ObjectID `json:"id" bson:"_id"`
	RoleName       string             `json:"roleName" bson:"role_name"` // index
	Desc           string             `json:"desc" bson:"desc"`
	AccessNameList []string           `json:"accessNameList"`
}

type Access struct {
	ID           primitive.ObjectID `json:"id" bson:"_id"`
	AccessName   string             `json:"accessName" bson:"access_name"` // index
	AccessNameZH string             `json:"accessNameZh" bson:"access_name_zh"`
	URL          string             `json:"url" bson:"url"`
	Action       string             `json:"action" bson:"action"`
	Desc         string             `json:"desc" bson:"desc"`
}

//RelaUserRole is relationship from user to role
type RelaUserRole struct {
	ID       primitive.ObjectID `json:"id" bson:"_id"`
	UserName string             `json:"userName" bson:"user_name"` // index
	RoleName string             `json:"roleName" bson:"role_name"` // index
}

//RelaRoleAcs is relationship from role to access
type RelaRoleAcs struct {
	ID         primitive.ObjectID `json:"id" bson:"_id"`
	RoleName   string             `json:"roleName" bson:"role_name"`     // index
	AccessName string             `json:"accessName" bson:"access_name"` // index
}

func NewUserBson(userName string, pwd string, title string) bson.M {
	return bson.M{
		"user_name": userName,
		"pwd":       pwd,
		"title":     title,
	}
}

func NewUserFilter(userName string) bson.M {
	return bson.M{
		IdxUser: userName,
	}
}

func NewRoleBson(roleName string) bson.M {
	return bson.M{
		"role_name": roleName,
	}
}

func NewAccessBson(accessName, accessNameZH, url string) bson.M {
	return bson.M{
		"access_name":    accessName,
		"access_name_zh": accessNameZH,
		"url":            url,
	}
}

func NewRelationUserRole(userName, roleName string) bson.M {
	return bson.M{
		"user_name": userName,
		"role_name": roleName,
	}
}

func NewRelationRoleAccess(roleName, accessName string) bson.M {
	return bson.M{
		"role_name":   roleName,
		"access_name": accessName,
	}
}

func SuperAdminBson() bson.M {
	return NewUserBson(DEFAULT_SUPER_ADMIN_USER, "12345", "超级管理员")
}

func SuperAdminRela() bson.M {
	return NewRelationUserRole(DEFAULT_SUPER_ADMIN_USER, ROLE_SUPERADMIN)
}

func AllRole() []interface{} {
	all := make([]interface{}, 0, 50)
	all = append(all, NewRoleBson(ROLE_SUPERADMIN))
	all = append(all, NewRoleBson(ROLE_ADMIN))
	all = append(all, NewRoleBson(ROLE_HIGHLEVEL))
	all = append(all, NewRoleBson(ROLE_NORMAL))
	all = append(all, NewRoleBson(ROLE_VISITOR))
	return all
}

func AllAccess() []interface{} {
	all := make([]interface{}, 0, 50)

	all = append(all, NewAccessBson(ACCESS_COMPLIANCE, ACCESS_COMPLIANCE_ZH, URL_COMPLIANCE))
	all = append(all, NewAccessBson(ACCESS_SETTING, ACCESS_SETTING_ZH, URL_SETTING))
	all = append(all, NewAccessBson(ACCESS_RUNTIME_DETECTION, ACCESS_RUNTIME_DETECTION_ZH, URL_RUNTIME_DETECTION))
	all = append(all, NewAccessBson(ACCESS_IMAGE_VULNERBILTY, ACCESS_IMAGE_VULNERBILTY_ZH, URL_IMAGE_VULNERBILTY))
	all = append(all, NewAccessBson(ACCESS_ONLINE_VULNERBILTY, ACCESS_ONLINE_VULNERBILTY_ZH, URL_ONLINE_VULNERBILTY))
	all = append(all, NewAccessBson(ACCESS_SUPER_ADMIN, ACCESS_SUPER_ADMIN_ZH, URL_SUPER_ADMIN))

	all = append(all, NewAccessBson(ACCESS_MICROSERVICE, ACCESS_MICROSERVICE_ZH, URL_MICROSERVICE))

	all = append(all, NewAccessBson(ACCESS_ALERTS, ACCESS_ALERTS_ZH, URL_ALERTS))
	all = append(all, NewAccessBson(ACCESS_AUDIT, ACCESS_AUDIT_ZH, URL_AUDIT))
	all = append(all, NewAccessBson(ACCESS_CLEANUP, ACCESS_CLEANUP_ZH, URL_CLEANUP))

	return all
}

func AllAccessURL() ([]string, map[string]struct{}) {
	return []string{
			URL_COMPLIANCE,
			URL_SETTING,
			URL_RUNTIME_DETECTION,
			URL_IMAGE_VULNERBILTY,
			URL_ONLINE_VULNERBILTY,
			URL_SUPER_ADMIN,
			URL_ALERTS,
			URL_AUDIT,
			URL_CLEANUP,
			URL_MICROSERVICE,
		},
		map[string]struct{}{
			URL_COMPLIANCE:         {},
			URL_SETTING:            {},
			URL_RUNTIME_DETECTION:  {},
			URL_IMAGE_VULNERBILTY:  {},
			URL_ONLINE_VULNERBILTY: {},
			URL_SUPER_ADMIN:        {},
			URL_ALERTS:             {},
			URL_AUDIT:              {},
			URL_CLEANUP:            {},
		}
}

func AllIgnoreAccessURL() ([]string, map[string]struct{}) {
	return []string{
			IGNORE_ACCESS_URL_AUTH,
			IGNORE_ACCESS_URL_USER,
			IGNORE_ACCESS_URL_PING,
			IGNORE_ACCESS_URL_SWAGGER,
			IGNORE_ACCESS_URL_HARBOR,
		},
		map[string]struct{}{
			IGNORE_ACCESS_URL_AUTH:    {},
			IGNORE_ACCESS_URL_USER:    {},
			IGNORE_ACCESS_URL_PING:    {},
			IGNORE_ACCESS_URL_SWAGGER: {},
			IGNORE_ACCESS_URL_HARBOR:  {},
		}
}

func DefaultRoleAccessRela() []interface{} {
	all := make([]interface{}, 0, 50)

	all = append(all, NewRelationRoleAccess(ROLE_SUPERADMIN, ACCESS_COMPLIANCE))
	all = append(all, NewRelationRoleAccess(ROLE_SUPERADMIN, ACCESS_SETTING))
	all = append(all, NewRelationRoleAccess(ROLE_SUPERADMIN, ACCESS_RUNTIME_DETECTION))
	all = append(all, NewRelationRoleAccess(ROLE_SUPERADMIN, ACCESS_IMAGE_VULNERBILTY))
	all = append(all, NewRelationRoleAccess(ROLE_SUPERADMIN, ACCESS_ONLINE_VULNERBILTY))
	all = append(all, NewRelationRoleAccess(ROLE_SUPERADMIN, ACCESS_SUPER_ADMIN))
	all = append(all, NewRelationRoleAccess(ROLE_SUPERADMIN, ACCESS_MICROSERVICE))
	all = append(all, NewRelationRoleAccess(ROLE_SUPERADMIN, ACCESS_ALERTS))
	all = append(all, NewRelationRoleAccess(ROLE_SUPERADMIN, ACCESS_AUDIT))
	all = append(all, NewRelationRoleAccess(ROLE_SUPERADMIN, ACCESS_CLEANUP))

	all = append(all, NewRelationRoleAccess(ROLE_ADMIN, ACCESS_COMPLIANCE))
	all = append(all, NewRelationRoleAccess(ROLE_ADMIN, ACCESS_SETTING))
	all = append(all, NewRelationRoleAccess(ROLE_ADMIN, ACCESS_RUNTIME_DETECTION))
	all = append(all, NewRelationRoleAccess(ROLE_ADMIN, ACCESS_COMPLIANCE))
	all = append(all, NewRelationRoleAccess(ROLE_ADMIN, ACCESS_ONLINE_VULNERBILTY))

	return all
}

func IdxUserColl() mongo.IndexModel {
	return mongo.IndexModel{
		Keys: bson.D{
			bson.E{
				Key:   IdxUser,
				Value: 1,
			},
		},
	}
}

func IdxRoleColl() mongo.IndexModel {
	return mongo.IndexModel{
		Keys: bson.D{
			bson.E{
				Key:   IdxRole,
				Value: 1,
			},
		},
	}
}

func IdxAccessColl() mongo.IndexModel {
	return mongo.IndexModel{
		Keys: bson.D{
			bson.E{
				Key:   IdxAccess,
				Value: 1,
			},
		},
	}
}

func IdxRelaUserRoleColl() (mongo.IndexModel, mongo.IndexModel) {
	return mongo.IndexModel{
			Keys: bson.D{
				bson.E{
					Key:   IdxRelaUR_1,
					Value: 1,
				},
			},
		}, mongo.IndexModel{
			Keys: bson.D{
				bson.E{
					Key:   IdxRelaUR_2,
					Value: 1,
				},
			},
		}
}

func IdxRelaRoleAccessColl() (mongo.IndexModel, mongo.IndexModel) {
	return mongo.IndexModel{
			Keys: bson.D{
				bson.E{
					Key:   IdxRelaRA_1,
					Value: 1,
				},
			},
		},
		mongo.IndexModel{
			Keys: bson.D{
				bson.E{
					Key:   IdxRelaRA_2,
					Value: 1,
				},
			},
		}
}
