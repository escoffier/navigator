package imagetrust

import (
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
