package kafkaAsset

import (
	"strings"
	"time"

	"scm.tensorsecurity.cn/tensorsecurity-rd/fanal/types"

	scannerUtils "gitlab.com/piccolo_su/vegeta/cmd/scanner/utils"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	imagesecTypes "gitlab.com/piccolo_su/vegeta/pkg/types/imagesec"
)

func GetRegImageInfo(data imagesecTypes.NodeReport) ([]*imagesecModel.Image,
	map[uint64][]*imagesecModel.ImageEnv) {
	images := make([]*imagesecModel.Image, 0)
	envs := make(map[uint64][]*imagesecModel.ImageEnv)

	for _, image := range data.RegImages {
		im := &imagesecModel.Image{
			ImageFromType: imagesecModel.ImageFromRegistry,
			ImageID:       image.ImageId,
			Size:          image.Size,
			Layer:         image.Layers,
			BuildAt:       GetBuildAt(image.Created),
			PullCount:     image.PullCount,
			User:          image.User,
			RegID:         data.RegInfo.RegID,
			Heartbeat:     time.Now().UnixMilli(),
		}
		split := strings.Split(image.Os, ":")
		if len(split) >= 2 {
			im.OS = types.OS{Family: split[0], Name: split[1], Eosl: false} // Eosl 表示不再维护
		}

		// 对于重复构建的相同名的镜像，前一次的镜像只有ID，没有repoTags,但是可以通过这个ID运行起容器
		if len(image.RepoTags) == 0 {
			im.Serialize()
			images = append(images, im)
			envs[im.UniqueID] = append(envs[im.UniqueID], ParseImageEnv(im.UniqueID, image.ENVS)...)
		}

		for _, repoTag := range image.RepoTags {
			host, repo, tag := scannerUtils.ParseImageName(repoTag)
			im.Host, im.Repo, im.Tag, im.Project = host, repo, tag, GetProject(repo)

			// 本地镜像没有推送到仓库，是没有digest的
			if len(image.Digests) == 0 {
				im2 := im.DeepCopy()
				im2.Serialize()
				images = append(images, im2)
				envs[im2.UniqueID] = append(envs[im2.UniqueID], ParseImageEnv(im2.UniqueID, image.ENVS)...)
			}
			for _, digest := range image.Digests {
				im.Digest = scannerUtils.GetSha256Digest(digest)
				im2 := im.DeepCopy()
				im2.Serialize()
				images = append(images, im2)
				envs[im2.UniqueID] = append(envs[im2.UniqueID], ParseImageEnv(im2.UniqueID, image.ENVS)...)
			}
		}
	}

	ans := make([]*imagesecModel.Image, 0)
	for i := range images {
		if err := images[i].Check(); err != nil {
			continue
		}
		ans = append(ans, images[i])
	}

	return ans, envs
}

func GetBuildAt(b string) int64 {
	// "2021-09-23T23:47:57.442225064Z",
	// "2023-09-02T03:27:37.119Z"
	// "2022-05-24 06:32:22.13 +0000 UTC"
	// "2022-05-24 06:33:49.022"

	split := strings.Split(b, ".")
	if len(split) > 0 {
		b = split[0]
	}

	key1 := "2006-01-02T15:04:05"
	key2 := "2006-01-02 15:04:05"

	ti1, _ := time.Parse(key1, b)
	ti2, _ := time.Parse(key2, b)
	if !ti1.IsZero() {
		return ti1.UnixMilli()
	}
	if !ti2.IsZero() {
		return ti2.UnixMilli()
	}
	return 0
}

func GetProject(p string) string {
	split := strings.Split(p, "/")
	return split[0]
}

func ParseImageEnv(imageUniqueID uint64, data []string) []*imagesecModel.ImageEnv {
	envs := make([]*imagesecModel.ImageEnv, 0)
	for i := range data {
		split := strings.Split(data[i], "=")

		if len(split) < 1 || split[0] == "" {
			continue
		}
		ev := &imagesecModel.ImageEnv{
			ImageUniqueID: imageUniqueID,
			Key:           split[0],
		}
		if len(split) == 2 {
			ev.Value = split[1]
		}
		envs = append(envs, ev)
	}
	return envs
}
