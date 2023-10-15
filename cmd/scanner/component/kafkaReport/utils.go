package imagesecReport

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/boltdb/bolt"
	"scm.tensorsecurity.cn/tensorsecurity-rd/fanal/types"
	trivyTypes "scm.tensorsecurity.cn/tensorsecurity-rd/trivy/pkg/types"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/vuln-updata/cnnvd"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/vuln-updata/cnvd"
	scannerUtils "gitlab.com/piccolo_su/vegeta/cmd/scanner/utils"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	imagesecTypes "gitlab.com/piccolo_su/vegeta/pkg/types/imagesec"
)

func GetVulnDetailFromBolt(vulnBoltDB *bolt.DB, vulnName string) (*trivyTypes.DetectedVulnerability, error) {
	vuln := trivyTypes.DetectedVulnerability{}
	err := vulnBoltDB.View(func(tx *bolt.Tx) error {
		var err error
		cnvdBucket := tx.Bucket([]byte("vulnerability"))
		if cnvdBucket == nil {
			return fmt.Errorf("not get vulnerability bucket")
		}
		cnvdBytes := cnvdBucket.Get([]byte(vulnName))
		if len(cnvdBytes) == 0 {
			return fmt.Errorf("not get %s vuln data", vulnName)
		}

		err = json.Unmarshal(cnvdBytes, &vuln)
		if err != nil {
			return err
		}
		return nil
	})
	return &vuln, err
}

func GetCnnvdFromBolt(cnnvdBoltDB *bolt.DB, vulnName string) (*cnnvd.VulnerabilityInfo, error) {
	cnnvdRes := cnnvd.VulnerabilityInfo{}
	err := cnnvdBoltDB.View(func(tx *bolt.Tx) error {
		var err error
		cnvdBucket := tx.Bucket([]byte("cnnvd"))
		if cnvdBucket == nil {
			return fmt.Errorf("not get cnnvd bucket")
		}
		cnvdBytes := cnvdBucket.Get([]byte(vulnName))
		if len(cnvdBytes) == 0 {
			return fmt.Errorf("not get %s cnnvd data", vulnName)
		}

		err = json.Unmarshal(cnvdBytes, &cnnvdRes)
		if err != nil {
			return err
		}
		return nil
	})
	return &cnnvdRes, err
}

func GetCnvdFromBolt(cnvdBoltDB *bolt.DB, vulnName string) ([]cnvd.Metadata, error) {
	cnvdRes := make([]cnvd.Metadata, 0)
	err := cnvdBoltDB.View(func(tx *bolt.Tx) error {
		var err error
		cnvdBucket := tx.Bucket([]byte("cnvd"))
		if cnvdBucket == nil {
			return fmt.Errorf("not get cnvd bucket")
		}
		cnvdBytes := cnvdBucket.Get([]byte(vulnName))
		if len(cnvdBytes) == 0 {
			return fmt.Errorf("not get %s cnvd data", vulnName)
		}

		err = json.Unmarshal(cnvdBytes, &cnvdRes)
		if err != nil {
			return err
		}
		return nil
	})
	return cnvdRes, err
}

func MkEmptyDir(path string) error {
	_ = os.RemoveAll(path)

	if err := os.MkdirAll(path, os.ModePerm); err != nil {
		return err
	}
	return nil
}

func OpenBoltDB(path string) (*bolt.DB, error) {
	options := bolt.Options{
		Timeout:  time.Second * 10,
		ReadOnly: true,
	}
	options.Timeout = time.Second * 15
	db, err := bolt.Open(string(path), 0600, &options)
	if err != nil {
		return nil, err
	}
	return db, nil
}

func CopyFile(pre, after string) error {
	if err := copyFile(pre, after); err != nil {
		return err
	}
	return nil
}

func copyFile(source, destination string) error {
	sourceFile, err := os.Open(source)
	if err != nil {
		return err
	}
	defer func() { _ = sourceFile.Close() }()

	destinationFile, err := os.Create(destination)
	if err != nil {
		return err
	}

	defer func() { _ = destinationFile.Close() }()

	_, err = io.Copy(destinationFile, sourceFile)
	if err != nil {
		return err
	}

	err = destinationFile.Sync()
	if err != nil {
		return err
	}
	return nil
}

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
			BuildAt:       getBuildAt(image.Created),
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
			envs[im.UniqueID] = append(envs[im.UniqueID], parseImageEnv(im.UniqueID, image.ENVS)...)
		}

		for _, repoTag := range image.RepoTags {
			host, repo, tag := scannerUtils.ParseImageName(repoTag)
			im.Host, im.Repo, im.Tag, im.Project = host, repo, tag, getProject(repo)

			// 本地镜像没有推送到仓库，是没有digest的
			if len(image.Digests) == 0 {
				im2 := im.DeepCopy()
				im2.Serialize()
				images = append(images, im2)
				envs[im2.UniqueID] = append(envs[im2.UniqueID], parseImageEnv(im2.UniqueID, image.ENVS)...)
			}
			for _, digest := range image.Digests {
				im.Digest = scannerUtils.GetSha256Digest(digest)
				im2 := im.DeepCopy()
				im2.Serialize()
				images = append(images, im2)
				envs[im2.UniqueID] = append(envs[im2.UniqueID], parseImageEnv(im2.UniqueID, image.ENVS)...)
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

func (s *ImageReport) GetNodeImageInfo(data imagesecTypes.NodeReport) ([]*imagesecModel.Image, *imagesecModel.NodeInfo,
	map[uint64][]*imagesecModel.ImageEnv) {
	//  contanerd 会有这样的数据，要处理
	//  digests=["docker.io/maohaoxin/syslog_upd_app_linux@sha256:b2d3f7e9af1d16382539dc3c330acc7d2d5cd2109d0eeff0f60679769bc91f55"]
	//  imageId=sha256:f66e9f553ba9899c5802abc1ebd9868f7bebe7bee406b5489d47550b8b15c210
	//  repoTags=["sha256:f66e9f553ba9899c5802abc1ebd9868f7bebe7bee406b5489d47550b8b15c210"]

	images := make([]*imagesecModel.Image, 0)
	envs := make(map[uint64][]*imagesecModel.ImageEnv)

	node := &imagesecModel.NodeInfo{
		IP:         data.NodeInfo.Ip,
		Hostname:   data.NodeInfo.HostName,
		ClusterKey: data.NodeInfo.ClusterKey,
		// AviraDB:    data.ReportDBVersion.AviraDBVersion, todo(下期功能)
	}

	node.UniqueID = node.GenUniqueID()

	for _, image := range data.NodeImages {
		im := &imagesecModel.Image{
			ImageFromType: imagesecModel.ImageFromNode,
			ImageID:       image.ImageId,
			Size:          image.Size,
			Layer:         image.Layers,
			BuildAt:       getBuildAt(image.Created),
			User:          image.User,
			NodeID:        node.UniqueID,
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

			envs[im.UniqueID] = append(envs[im.UniqueID], parseImageEnv(im.UniqueID, image.ENVS)...)
		}

		for _, repoTag := range image.RepoTags {
			host, repo, tag := scannerUtils.ParseImageName(repoTag)
			im.Host, im.Repo, im.Tag, im.Project = host, repo, tag, getProject(repo)

			// 本地镜像没有推送到仓库，是没有digest的
			if len(image.Digests) == 0 {
				im2 := im.DeepCopy()
				im2.Serialize()
				images = append(images, im2)
				envs[im2.UniqueID] = append(envs[im2.UniqueID], parseImageEnv(im2.UniqueID, image.ENVS)...)
			}
			for _, digest := range image.Digests {
				im.Digest = scannerUtils.GetSha256Digest(digest)
				im2 := im.DeepCopy()
				im2.Serialize()
				images = append(images, im2)
				envs[im2.UniqueID] = append(envs[im2.UniqueID], parseImageEnv(im2.UniqueID, image.ENVS)...)
				images = append(images, im.DeepCopy())
			}
		}
	}

	ans := make([]*imagesecModel.Image, 0)
	for i := range images {
		if err := images[i].Check(); err != nil {
			s.Log.Debug().Str("image", images[i].GetImageName()).Msg("image check")
			continue
		}
		ans = append(ans, images[i])
	}

	return ans, node, envs
}

func getBuildAt(b string) int64 {
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

func getProject(p string) string {
	split := strings.Split(p, "/")
	return split[0]
}

func parseImageEnv(imageUniqueID uint64, data []string) []*imagesecModel.ImageEnv {
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

func GetLicense(l string) []string {
	ans := make([]string, 0)
	split := strings.Split(l, " ")
	for i := range split {
		if split[i] != "" {
			ans = append(ans)
		}
	}
	return ans
}
