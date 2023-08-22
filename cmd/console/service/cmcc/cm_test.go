package cmcc

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"gitlab.com/security-rd/go-pkg/databases"
)

var cmUserList = &CMUserList{
	Total: 10,
	Code:  200,
	Data: []CMUser{
		{
			UserID:        1,
			UserName:      "zhangming",
			Alias:         "zhangming-alias",
			Password:      "FktXsD2dsjS7Refk/togDQ==",
			Sex:           1,
			Phone:         "13000000001",
			Email:         "123@qq.com",
			Address:       "探真科技",
			Status:        1,
			CreateID:      1,
			CreateTime:    "2023-05-25 10:46:41",
			UserPhotoID:   1,
			OrgID:         1,
			OrgName:       "集团公司",
			SourceType:    1,
			UserAccount:   "",
			LoginTimes:    0,
			LastLoginTime: "2023-05-25 10:46:41",
		},
		{
			UserID:        2,
			UserName:      "zhangsan",
			Alias:         "zhangsan-alias",
			Password:      "FktXsD2dsjS7Refk/togDQ==",
			Sex:           1,
			Phone:         "13000000001",
			Email:         "123@qq.com",
			Address:       "探真科技",
			Status:        1,
			CreateID:      1,
			CreateTime:    "2023-05-25 10:46:41",
			UserPhotoID:   1,
			OrgID:         1,
			OrgName:       "集团公司",
			SourceType:    1,
			UserAccount:   "",
			LoginTimes:    0,
			LastLoginTime: "2023-05-25 10:46:41",
		},
		{
			UserID:        3,
			UserName:      "zhanger",
			Alias:         "zhanger-alias",
			Password:      "FktXsD2dsjS7Refk/togDQ==",
			Sex:           1,
			Phone:         "13000000001",
			Email:         "123@qq.com",
			Address:       "探真科技",
			Status:        1,
			CreateID:      1,
			CreateTime:    "2023-05-25 10:46:41",
			UserPhotoID:   1,
			OrgID:         1,
			OrgName:       "集团公司",
			SourceType:    1,
			UserAccount:   "",
			LoginTimes:    0,
			LastLoginTime: "2023-05-25 10:46:41",
		},
		{
			UserID:        4,
			UserName:      "zhangsi",
			Alias:         "zhangsi-alias",
			Password:      "FktXsD2dsjS7Refk/togDQ==",
			Sex:           1,
			Phone:         "13000000001",
			Email:         "123@qq.com",
			Address:       "探真科技",
			Status:        1,
			CreateID:      1,
			CreateTime:    "2023-05-25 10:46:41",
			UserPhotoID:   1,
			OrgID:         1,
			OrgName:       "集团公司",
			SourceType:    1,
			UserAccount:   "",
			LoginTimes:    0,
			LastLoginTime: "2023-05-25 10:46:41",
		},
		{
			UserID:        5,
			UserName:      "zhangwu",
			Alias:         "zhangwu-alias",
			Password:      "FktXsD2dsjS7Refk/togDQ==",
			Sex:           1,
			Phone:         "13000000001",
			Email:         "123@qq.com",
			Address:       "探真科技",
			Status:        1,
			CreateID:      1,
			CreateTime:    "2023-05-25 10:46:41",
			UserPhotoID:   1,
			OrgID:         1,
			OrgName:       "集团公司",
			SourceType:    1,
			UserAccount:   "",
			LoginTimes:    0,
			LastLoginTime: "2023-05-25 10:46:41",
		},
		{
			UserID:        6,
			UserName:      "zhangliu",
			Alias:         "zhangliu-alias",
			Password:      "FktXsD2dsjS7Refk/togDQ==",
			Sex:           1,
			Phone:         "13000000001",
			Email:         "123@qq.com",
			Address:       "探真科技",
			Status:        1,
			CreateID:      1,
			CreateTime:    "2023-05-25 10:46:41",
			UserPhotoID:   1,
			OrgID:         1,
			OrgName:       "集团公司",
			SourceType:    1,
			UserAccount:   "",
			LoginTimes:    0,
			LastLoginTime: "2023-05-25 10:46:41",
		},
		{
			UserID:        7,
			UserName:      "zhangqi",
			Alias:         "zhangqi-alias",
			Password:      "FktXsD2dsjS7Refk/togDQ==",
			Sex:           1,
			Phone:         "13000000001",
			Email:         "123@qq.com",
			Address:       "探真科技",
			Status:        1,
			CreateID:      1,
			CreateTime:    "2023-05-25 10:46:41",
			UserPhotoID:   1,
			OrgID:         1,
			OrgName:       "集团公司",
			SourceType:    1,
			UserAccount:   "",
			LoginTimes:    0,
			LastLoginTime: "2023-05-25 10:46:41",
		},
		{
			UserID:        8,
			UserName:      "zhangba",
			Alias:         "zhangba-alias",
			Password:      "FktXsD2dsjS7Refk/togDQ==",
			Sex:           1,
			Phone:         "13000000001",
			Email:         "123@qq.com",
			Address:       "探真科技",
			Status:        1,
			CreateID:      1,
			CreateTime:    "2023-05-25 10:46:41",
			UserPhotoID:   1,
			OrgID:         1,
			OrgName:       "集团公司",
			SourceType:    1,
			UserAccount:   "",
			LoginTimes:    0,
			LastLoginTime: "2023-05-25 10:46:41",
		},
		{
			UserID:        9,
			UserName:      "zhangjiu",
			Alias:         "zhangjiu-alias",
			Password:      "FktXsD2dsjS7Refk/togDQ==",
			Sex:           1,
			Phone:         "13000000001",
			Email:         "123@qq.com",
			Address:       "探真科技",
			Status:        1,
			CreateID:      1,
			CreateTime:    "2023-05-25 10:46:41",
			UserPhotoID:   1,
			OrgID:         1,
			OrgName:       "集团公司",
			SourceType:    1,
			UserAccount:   "",
			LoginTimes:    0,
			LastLoginTime: "2023-05-25 10:46:41",
		},
		{
			UserID:        10,
			UserName:      "zhangshi",
			Alias:         "zhangshi-alias",
			Password:      "FktXsD2dsjS7Refk/togDQ==",
			Sex:           1,
			Phone:         "13000000001",
			Email:         "123@qq.com",
			Address:       "探真科技",
			Status:        1,
			CreateID:      1,
			CreateTime:    "2023-05-25 10:46:41",
			UserPhotoID:   1,
			OrgID:         1,
			OrgName:       "集团公司",
			SourceType:    1,
			UserAccount:   "",
			LoginTimes:    0,
			LastLoginTime: "2023-05-25 10:46:41",
		},
	},
}

func panicOnError(err error) {
	if err != nil {
		panic(err)
	}
}
func setupRDB() *databases.RDBInstance {
	opt := databases.Options{
		RdbUser:         "ivan",
		RdbHost:         "192.168.3.10",
		RdbPassword:     "Mysql-ha@123",
		RdbPort:         30036,
		RdbDbname:       "ivan",
		RdbReadonlyHost: "192.168.3.10",
	}

	c, err := databases.NewRDBClient(&opt)

	panicOnError(err)
	return c
}

func TestUpsertAllUsers(t *testing.T) {
	s := NewCMUserService(setupRDB(), "", "", "", "")

	err := s.upsertUsers(context.Background(), cmUserList.Data)
	panicOnError(err)
}

var msgs = []CMUserMsg{
	{
		OperationType: "add",
		User: CMUser{
			UserID:   20,
			UserName: "huangpengxiang",
			CreateID: 9,
			Alias:    "黄鹏祥",
			Email:    "huangpengxiang@chinamobile.com",
			OrgID:    1,
			OrgName:  "集团公司",
			Password: "5aG/QxqWxf/kQYDTSNF2Bw==",
			Phone:    "1512719813",
			Status:   1,
		},
		OperationTime: "2023-05-25 11:06:54",
	},
	{
		OperationType: "change",
		User: CMUser{
			UserID:   20,
			UserName: "huangpengxiang",
			CreateID: 9,
			Alias:    "黄鹏祥11",
			Email:    "huangpengxiang@chinamobile.com",
			OrgID:    1,
			OrgName:  "集团公司",
			Password: "5aG/QxqWxf/kQYDTSNF2Bw==",
			Phone:    "1512719813",
			Status:   1,
		},
		OperationTime: "2023-05-25 11:06:59",
	},
	{
		OperationType: "resetpwd",
		User: CMUser{
			UserID:   20,
			UserName: "huangpengxiang",
			CreateID: 9,
			Alias:    "黄鹏祥11",
			Email:    "huangpengxiang@chinamobile.com",
			OrgID:    1,
			OrgName:  "集团公司",
			Password: "UmVkaXMxMjM0NQ==",
			Phone:    "1512719813",
			Status:   1,
		},
		OperationTime: "2023-05-25 11:07:54",
	},
	{
		OperationType: "chgstatus",
		User: CMUser{
			UserID:   20,
			UserName: "huangpengxiang",
			CreateID: 9,
			Alias:    "黄鹏祥11",
			Email:    "huangpengxiang@chinamobile.com",
			OrgID:    1,
			OrgName:  "集团公司",
			Password: "UmVkaXMxMjM0NQ==",
			Phone:    "1512719813",
			Status:   -1,
		},
		OperationTime: "2023-05-25 11:08:54",
	},
	{
		OperationType: "delete",
		User: CMUser{
			UserID:   20,
			UserName: "huangpengxiang",
			CreateID: 9,
			Alias:    "黄鹏祥11",
			Email:    "huangpengxiang@chinamobile.com",
			OrgID:    1,
			OrgName:  "集团公司",
			Password: "UmVkaXMxMjM0NQ==",
			Phone:    "1512719813",
			Status:   -1,
		},
		OperationTime: "2023-05-25 11:09:54",
	},
	{
		OperationType: "add",
		User: CMUser{
			UserID:   21,
			UserName: "huangpengxiang22",
			CreateID: 9,
			Alias:    "黄鹏祥22",
			Email:    "huangpengxiang@chinamobile.com",
			OrgID:    1,
			OrgName:  "集团公司",
			Password: "UmVkaXMxMjM0NQ==",
			Phone:    "1512719813",
			Status:   1,
		},
		OperationTime: "2023-05-25 11:10:54",
	},
	{
		OperationType: "delete",
		User: CMUser{
			UserID:   21,
			UserName: "huangpengxiang22",
			CreateID: 9,
			Alias:    "黄鹏祥22",
			Email:    "huangpengxiang@chinamobile.com",
			OrgID:    1,
			OrgName:  "集团公司",
			Password: "UmVkaXMxMjM0NQ==",
			Phone:    "1512719813",
			Status:   1,
		},
		OperationTime: "2023-05-25 11:11:54",
	},
	{
		OperationType: "add",
		User: CMUser{
			UserID:   22,
			UserName: "huangpengxiang33",
			CreateID: 9,
			Alias:    "黄鹏祥33",
			Email:    "huangpengxiang@chinamobile.com",
			OrgID:    1,
			OrgName:  "集团公司",
			Password: "5aG/QxqWxf/kQYDTSNF2Bw==",
			Phone:    "1512719813",
			Status:   1,
		},
		OperationTime: "2023-05-25 11:12:54",
	},
}

func TestHandleCMUserMsg(t *testing.T) {
	s := NewCMUserService(setupRDB(), "", "", "", "")

	for _, msg := range msgs {
		data, err := json.Marshal(msg)
		panicOnError(err)

		err = s.handleCMUserMsg(context.Background(), data)
		panicOnError(err)
	}
}

func TestCMUser(t *testing.T) {
	setupCMOption()
	cmOpt, err := GetCMUserOption()
	if err != nil {
		t.Fatal(err)
	}

	cm, err := InitCMUserService(setupRDB(), cmOpt.Appid, cmOpt.APIHost, cmOpt.APIKey, "")
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err = cm.StartSubscribeCMUserMsg(ctx, cmOpt.PulsarURL)
	if err != nil {
		t.Fatal(err)
	}

	time.Sleep(30 * time.Second)

}

func setupCMOption() {
	os.Setenv(CMAPIHostEnvKey, "http://localhost:10008")
	os.Setenv(CMAPIKeyEnvKey, "api_key")
	os.Setenv(CMAuthKeyEnvKey, "fake")
	os.Setenv(CMPulsarURLEnvKey, "pulsar://localhost:6650")
}

func TestUnmarshal(t *testing.T) {
	src := `{
		"operationType":"add",
		"user":{
			"userId":20,
			"userName":"huangpengxiang",
			"alias":"黄鹏祥",
			"password":"5aG/QxqWxf/kQYDTSNF2Bw==",
			"sex":0,
			"phone":"1512719813",
			"email":"huangpengxiang@chinamobile.com",
			"address":"",
			"status":1,
			"createId":9,
			"createTime":"",
			"updateTime":"",
			"userPhotoId":0,
			"orgId":1,
			"orgName":"集团公司",
			"sourceType":0,
			"userAccount":"",
			"loginTimes":0,
			"lastLoginTime":"",
			"departmentId":"",
			"DepartmentName":""
		},
		"operationTime":"2023-05-25 11:06:54"
	}`

	msg := &CMUserMsg{}
	err := json.Unmarshal([]byte(src), msg)
	if err != nil {
		t.Fatal(err)
	}

	operationTime, err := time.Parse(time.DateTime, msg.OperationTime)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(operationTime)
}

func TestJWTTokenParse(t *testing.T) {
	tokenString := `eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJtaW5odWkiLCJhdWQiOiJjb20uYWlmLnBhYXMud2ViVG9rZW4iLCJ1c2VySW5mbyI6IntcImFsaWFzXCI6XCJtaW5odWlcIixcImVtYWlsXCI6XCJkZURleXh0cGVBeGFackxJOU9BMjl1Q1FCT0dnYk9zOFwiLFwib3JnSWRcIjoxMDAsXCJvcmdOYW1lXCI6XCLpm4blm6Llhazlj7hcIixcInBob25lXCI6XCJXd1NDR1VWYXhiSHphcVo3eGRNRnR3PT1cIixcInJvbGVMaXN0XCI6W3tcInJvbGVDb2RlXCI6XCJzeXMtYWRtaW5cIixcInJvbGVOYW1lXCI6XCLns7vnu5_nrqHnkIZcIn1dLFwidXNlcklkXCI6MTAwMDc5LFwidXNlck5hbWVcIjpcIm1pbmh1aVwifSIsImlzcyI6ImFzaWFpbmZvLmNvbSIsImV4cCI6MTY4NjY0OTk5MX0.slYosUk_r9TUa6vei9z568k8-6HGC2IY-i8CjNu83Uc`

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		// hmacSampleSecret is a []byte containing your secret, e.g. []byte("my_secret_key")
		return []byte(cmAuthKey), nil
	})

	if claims, ok := token.Claims.(jwt.MapClaims); ok {

		for k, v := range claims {
			fmt.Println(k, v)
		}
	} else {
		fmt.Println(err)
	}

}

func TestOldJWTTokenParse(t *testing.T) {
	tokenString := `eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiIsImF1ZCI6ImNvbS5haWYucGFhcy53ZWJUb2tlbiIsInVzZXJJbmZvIjoie1wiYWxpYXNcIjpcImFkbWluXCIsXCJyb2xlTGlzdFwiOlt7XCJyb2xlQ29kZVwiOlwiYWRtaW5cIixcInJvbGVOYW1lXCI6XCLotoXnuqfnrqHnkIblkZhcIn1dLFwidXNlcklkXCI6MSxcInVzZXJOYW1lXCI6XCJhZG1pblwifSIsImlzcyI6ImFzaWFpbmZvLmNvbSIsImV4cCI6MTY4NTUwMzE0NH0.3QGlJQfLO2OjVQdJxCHq1oxYgtBq4CJ4DXv7nlzvn5w`

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		// hmacSampleSecret is a []byte containing your secret, e.g. []byte("my_secret_key")
		return []byte(cmAuthKey), nil
	})

	if claims, ok := token.Claims.(jwt.MapClaims); ok {

		for k, v := range claims {
			fmt.Println(k, v)
		}
	} else {
		fmt.Println(err)
	}

}

func TestGetDefaultAuth(t *testing.T) {
	s := NewCMUserService(setupRDB(), "", "", "", "")

	modules, err := s.getDefaultAuth(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println(modules)

}
