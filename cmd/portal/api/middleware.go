package api

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"gitlab.com/piccolo_su/vegeta/cmd/portal/component/token"
	"gitlab.com/piccolo_su/vegeta/cmd/portal/store"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

func AddLanguage(ctx *gin.Context) {
	ctx.Set(imagesecModel.AcceptLanguage, util.GetLanguage(ctx))
}

func GenTokenAuthMiddleware(ud store.UserDal) gin.HandlerFunc {
	return func(c *gin.Context) {
		// 从请求头中获取 Token
		tm := token.NewJWTTokenManager(ud)
		to := c.GetHeader("Authorization")
		if to == "" {
			to = c.GetHeader("authorization")
		}
		to = strings.TrimLeft(to, "Bearer")
		to = strings.TrimSpace(to)

		p, err := tm.Verify(to)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			c.Abort()
			return
		}
		c.Set("Account", p.PortalEmail)
		c.Set("Payload", p)
		// 继续处理请求
		c.Next()
	}
}
