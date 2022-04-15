package api

import (
	"github.com/gin-gonic/gin"

	"gitlab.com/piccolo_su/vegeta/cmd/webshell-server/api/detector"
)

func InitRouter(router *gin.Engine) {
	v1 := router.Group("/v1")
	{
		Detector(v1)
	}
}

func Detector(group gin.IRouter) {
	api := detector.NewAPIServer()
	group.POST("/:type/detector", api.File)
}
