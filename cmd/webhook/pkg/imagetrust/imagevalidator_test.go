package imagetrust

import (
	"encoding/base64"
	"encoding/json"
	"testing"
)

func TestName(t *testing.T) {
	validation := &ImageValidatorReq{}
	img := RejectOnlineMonitorImage{
		Image:    "222",
		FromType: "333",
		Digest:   "3444444",
	}
	validation.Images = append(validation.Images, img)

	data, err := json.Marshal(validation)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(data))
}

func TestBase64(t *testing.T) {
	auth := "devops:Hrbr12@Tensor.*#)"
	encoder := base64.StdEncoding
	data, err := encoder.DecodeString("ZGV2b3BzOkhyYnIxMkBUZW5zb3IuKiMp")
	if err != nil || string(data) != auth {
		t.Fatal(err)
	}
}
