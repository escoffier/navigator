package validator

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"strings"

	log "github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
)

type RejectOnlineMonitorImage struct {
	Image    string `json:"image"`
	FromType string `json:"type"`
	//CustomKV []KVHash `json:"custom_KV"` //自定义kv
}

type Result struct {
	ApiVersion string `json:"apiVersion"`
	Data       Data   `json:"data"`
}

type Data struct {
	Item Item `json:"item"`
}

type Item struct {
	Flag bool `json:"flag"`
}

type ImageValidatorReq struct {
	Images []RejectOnlineMonitorImage
}

func (v *PodValidator) ValidateImage(pod *v1.Pod) error {
	reqs := buildRequest(pod)
	var err error
	var data []byte
	var resp *http.Response
	data, err = json.Marshal(reqs.Images)
	if err != nil {
		return err
	}

	resp, err = http.Post(v.validatorUrl, "application/json", bytes.NewReader(data))
	if err != nil {
		log.Warn(err)
		return nil
	}
	defer resp.Body.Close()

	var respBody []byte
	respBody, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Warn(err)
		return nil
	}

	log.Debugf("resp: %s", string(respBody))
	result := Result{}
	err = json.Unmarshal(respBody, &result)
	if err != nil {
		log.Warnf("Unmarshal response err %v", err)
		return nil
	}

	// image is unsafe, pod creation will be denied
	if !result.Data.Item.Flag {
		return errors.New("unsafe images")
	}
	return nil
}

//  containerStatuses:
//  - containerID: docker://23526afd26ea860bfc1f2c729b0b67da8f57ade5388855c27283d20df56ba95e
//    image: kennethreitz/httpbin:latest
//    imageID: docker-pullable://kennethreitz/httpbin@sha256:599fe5e5073102dbb0ee3dbb65f049dab44fa9fc251f6835c9990f8fb196a72b
//    lastState: {}
//    name: httpbin
func buildRequest(pod *v1.Pod) *ImageValidatorReq {
	req := &ImageValidatorReq{}
	for _, c := range pod.Spec.InitContainers {
		image := RejectOnlineMonitorImage{
			Image:    c.Image,
			FromType: "k8s_deployment",
		}
		req.Images = append(req.Images, image)
	}

	for _, c := range pod.Spec.Containers {
		image := RejectOnlineMonitorImage{
			Image:    c.Image,
			FromType: "k8s_deployment",
		}
		req.Images = append(req.Images, image)
	}
	return req
}

//func buildRequest(statuses []v1.ContainerStatus) *ImageValidatorReq {
//	req := &ImageValidatorReq{}
//	for _, status := range statuses {
//		image := RejectOnlineMonitorImage{
//			ContainerID:   getContainerID(status.ContainerID),
//			ContainerName: status.Name,
//			FullRepoName:  getFullRepoName(status.Image),
//			Library:       getLibrary(status.Image),
//			Digest:        getImageDigest(status.ImageID),
//			Tag:           getImageTag(status.Image),
//		}
//		req.Images = append(req.Images, image)
//	}
//	return req
//}

func getContainerID(containerID string) string {
	// docker://23526afd26ea860bfc1f2c729b0b67da8f57ade5388855c27283d20df56ba95e
	i := strings.LastIndex(containerID, "/")
	if i == -1 || (i+1 >= len(containerID)-1) {
		return ""
	}
	id := containerID[i+1:]
	return id
}

func getImageTag(image string) string {
	i := strings.LastIndex(image, ":")
	if i == -1 {
		return ""
	}

	// image like this: kennethreitz/httpbin:
	if i+1 >= len(image)-1 {
		return ""
	}

	tag := image[i+1:]
	return tag
}

func getImageDigest(imageID string) string {
	i := strings.LastIndex(imageID, ":")
	if i == -1 {
		return ""
	}

	// image like this: kennethreitz/httpbin:
	if i+1 >= len(imageID)-1 {
		return ""
	}

	digest := imageID[i+1:]
	return digest
}

// getLibrary get library from ContainerStatus.Image
func getLibrary(image string) string {
	index := strings.Index(image, "/")
	if strings.Contains(image, "http") {
		if index == -1 {
			return "https://" + image
		} else {
			return "https://" + image[:index]
		}
	} else {
		if index == -1 {
			return image
		} else {
			return image[:index]
		}
	}
}

func getFullRepoName(image string) string {
	return image
}
