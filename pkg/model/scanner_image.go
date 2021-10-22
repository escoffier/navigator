package model

type IsTrustedImagesResp struct {
	IsTrusted bool `json:"is_trusted"`
}

type SignImageTrustedReq struct {
	Image         string `json:"image" binding:"required"`
	Digest        string `json:"digest" binding:"required"`
	PrivateDigest string `json:"private_digest" binding:"required"`
	// sign = Sign(PrivateDigest Digest Image)  // 三个数据中间空格分割
	Sign     []byte `json:"sign" binding:"required"`
	Insecure bool   `json:"insecure"` // http or https
}
