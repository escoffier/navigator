package devicemapper

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/avast/retry-go"
	"github.com/docker/docker/api/types"
	"github.com/saracen/walker"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/dp/whitelist/analyzer"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/global"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/container"
	fs2 "gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/fs"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"gitlab.com/security-rd/go-pkg/logging"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	// dmsetup use a 24-bit num as deviceId,so the max num is 16777215. we use a magic number to avoid deviceId conflict
	snapDevId              = 6000215
	deviceIdConflict       = "File exists"
	snapName               = "ts-snap"
	snapMountDir           = "ts-img-snap"
	deviceMapperCmdTimeout = 5
)

var (
	// it is difficult to do parallel dm task (eg.allow dev id,create snap etc.),so we use a global lock to avoid parallel task
	// todo: support parallel dm task
	lock sync.Mutex
)

// devInfo contain image layer's device info in devicemapper
type devInfo struct {
	DeviceID      int    `json:"device_id"` // we only use device id
	Size          uint64 `json:"size"`
	TransactionID uint64 `json:"transaction_id"`
	Initialized   bool   `json:"initialized"`
	Deleted       bool   `json:"deleted"`
}

type DeviceMapper struct {
	runtimeDataDir   string            // runtime data dir. eg."/var/lib/docker" if run in local, or "/host/var/lib/docker" if run in container
	poolName         string            // thi-provision pool name,eg.docker-thin-pool
	poolDevName      string            // eg./host/dev/mapper/docker-thi-pool
	devPath          string            // eg./host/dev
	snapDevName      string            // eg./host/dev/mapper/ts-snap
	snapMountPath    string            // eg./host/var/lib/tensor/ts-img-snap
	allocateDeviceId int               // snap actual used device id
	mountOk          bool              // true: mount dev/mapper/ts-snap dir ok. defer umount if true
	snapOK           bool              // true: dmsetup create snap ok. defer remove snap if true
	messageOK        bool              // true: dmsetup message pool ok. defer delete msg if true
	execFileSet      map[string]string // eg./usr/bin/ls->1234
	execLock         sync.Mutex
}

func init() {
	err := analyzer.Register(analyzer.TypeDeviceMapper, NewAnalyzer)
	if err != nil {
		logging.Get().Err(err).Msg("failed to register devicemapper analyzer")
	} else {
		logging.Get().Debug().Msg("register devicemapper analyzer ok")
	}

}

func (d *DeviceMapper) Type() analyzer.Type {
	return analyzer.TypeDeviceMapper
}

func (d *DeviceMapper) Require(runtimeInfo types.Info) bool {
	return strings.Contains(runtimeInfo.Driver, "devicemapper")
}

func (d *DeviceMapper) Clean() error {
	_ = GetDmSetup().ClearFromFile()

	return nil
}

func (d *DeviceMapper) AnalyzeWhiteList(_ container.Runtime, runtimeInfo types.Info, image types.ImageInspect) (analyzer.ExecFiles, error) {
	lock.Lock()
	defer lock.Unlock()

	logging.Get().Info().Interface("image", image).Msg("start analyzing image exec file list")

	// defer clear
	defer func() { _ = d.clearDeviceMapper() }()

	// some prepare work
	err := d.prepare(runtimeInfo)
	if err != nil {
		logging.Get().Err(err).Interface("image", image.RepoTags).Msg("prepare work failed")
		return nil, err
	}

	// get top layer chain id
	diffIds := ApiTypeToRootFS(image.RootFS)
	chainId := CreateChainID(diffIds)
	logging.Get().Debug().Interface("image", image.RepoTags).Str("chainId", chainId.String()).Msg("generate chain id")

	// get device id from local file
	di, err := d.getDevInfoByChainId(chainId)
	if err != nil {
		logging.Get().Err(err).Interface("image", image.RepoTags).Str("chainId", chainId.String()).Msg("failed to get device id")
		return nil, err
	}
	logging.Get().Debug().Interface("devInfo", di).Msg("get device id from local file")

	// send create snap message to pool
	err = d.snapMessageToPool(di.DeviceID)
	if err != nil {
		logging.Get().Err(err).Interface("image", image.RepoTags).Int("devId", di.DeviceID).Msg("failed to send create snap msg")
		return nil, err
	}
	logging.Get().Debug().Interface("image", image.RepoTags).Msg("send snap msg ok")

	// create snap
	err = d.createSnap(image)
	if err != nil {
		logging.Get().Err(err).Interface("image", image.RepoTags).Msg("create snap err")
		return nil, err
	}
	logging.Get().Debug().Interface("image", image.RepoTags).Msg("create snap ok")

	// mount snap device to local path
	err = d.mountSnap()
	if err != nil {
		logging.Get().Err(err).Interface("image", image.RepoTags).Msg("failed to mount snap")
		return nil, err
	}

	// generate whitelist
	err = d.generateExecList()
	if err != nil {
		logging.Get().Err(err).Interface("image", image.RepoTags).Msg("failed to generate white list")
		return nil, err
	}
	logging.Get().Info().Interface("image", image.RepoTags).Msg("analyze exec file list ok")

	return d.execFileSet, nil
}

func (d *DeviceMapper) generateExecList() error {
	// rootfs: /host/var/lib/tensor/ts-img-snap/rootfs
	rootfs := filepath.Join(d.snapMountPath, "rootfs")

	addExecFunc := func(curFilePath, topPath string, fi os.FileInfo) {
		// file path in image,eg. /usr/local/bin/test.sh
		filePathInImage := strings.TrimPrefix(curFilePath, topPath)

		// calculate hash
		fileHash := fs2.FileHashCrc32(curFilePath, fi.Size())

		// use lock to append because walker.Walk will use multi goroutine concurrently
		d.appendExecFile(filePathInImage, fileHash)
	}

	err := walker.Walk(rootfs, func(pathname string, fi os.FileInfo) error {
		if fi.IsDir() {
			return nil
		}

		if fi.Mode()&os.ModeSymlink != 0 {
			// dp.so will readlink so we bypass link here
			return nil
		}

		if !fs2.IsExec(fi.Mode()) {
			return nil
		}

		addExecFunc(pathname, rootfs, fi)

		return nil
	})
	return err
}

func (d *DeviceMapper) appendExecFile(filePathInImage string, fileHash uint32) {
	d.execLock.Lock()
	defer d.execLock.Unlock()
	d.execFileSet[filePathInImage] = fmt.Sprintf("%X", fileHash)
}
func (d *DeviceMapper) isDeviceIdConflict(cmdMsg string) bool {
	return strings.Contains(cmdMsg, deviceIdConflict)
}

func (d *DeviceMapper) prepare(runtimeInfo types.Info) error {
	// data dir diff by run mode: local or container
	d.runtimeDataDir = global.RuntimeDataDir(runtimeInfo)

	// get pool name every time in case someone manually change devicemapper pool
	found := false
	for _, v := range runtimeInfo.DriverStatus {
		if strings.Contains(v[0], "Pool Name") {
			d.poolName = v[1]
			found = true
		}
	}
	if !found {
		return fmt.Errorf("not found pool name")
	}

	// get dev path
	devEnv := os.Getenv("DM_DEV_DIR")
	if len(devEnv) == 0 {
		logging.Get().Warn().Str("devEnv", devEnv).Msg("dev env is empty,dmsetup may function err")
		d.devPath = "/dev"
	} else {
		d.devPath = devEnv
	}

	// generate pool dev name
	d.poolDevName = filepath.Join(d.devPath, "mapper", d.poolName)

	// generate snap dev name
	d.snapDevName = filepath.Join(d.devPath, "mapper", snapName)

	// generate mount path.
	d.snapMountPath = filepath.Join(global.GetDpRealWorkingDir(), snapMountDir)
	if err := fs2.CleanCreateDir(d.snapMountPath); err != nil {
		logging.Get().Err(err).Str("snapMountPath", d.snapMountPath).Msg("failed to create snap mount dir")
		return err
	}

	logging.Get().Debug().
		Str("devPath", d.devPath).
		Str("poolName", d.poolName).
		Str("poolDevName", d.poolDevName).
		Str("snapDevName", d.snapDevName).
		Str("snapMountPath", d.snapMountPath).
		Msg("prepare work")

	return nil
}

// getDevInfoByChainId return devicemapper allocate device id for image layer
func (d *DeviceMapper) getDevInfoByChainId(chainId ChainID) (devInfo, error) {
	// layer host path
	arr := strings.Split(chainId.String(), ":")
	if len(arr) != 2 {
		return devInfo{}, fmt.Errorf("invalid chian id(%s),format should be sha256:xyz", chainId.String())
	}
	path := filepath.Join(d.runtimeDataDir, "image/devicemapper/layerdb/sha256/", arr[1], "cache-id")

	// get meta id
	data, err := os.ReadFile(path)
	if err != nil {
		return devInfo{}, err
	}
	metaId := string(data)
	logging.Get().Debug().Str("metaId", metaId).Str("chainId", chainId.String()).Msg("get meta id")

	// get device id
	deviceIdPath := filepath.Join(d.runtimeDataDir, "devicemapper/metadata/", metaId)
	deviceData, err := os.ReadFile(deviceIdPath)
	if err != nil {
		return devInfo{}, err
	}
	logging.Get().Debug().Str("deviceIdPath", deviceIdPath).Msg("get device file path")

	di := devInfo{}
	err = json.Unmarshal(deviceData, &di)
	if err != nil {
		return devInfo{}, err
	}

	return di, nil
}

// snapMessageToPool dmsetup require sending msg to pool before actual create
func (d *DeviceMapper) snapMessageToPool(layerDevId int) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(deviceMapperCmdTimeout)*time.Second)
	defer cancel()

	curSnapDevId := snapDevId
	// retry to avoid device id conflict
	err := util.RetryWithBackoff(ctx, func() error {
		// create msg cmd
		msgCmd := fmt.Sprintf("dmsetup message %s 0 \"create_snap %d %d\"", d.poolDevName, curSnapDevId, layerDevId)
		logging.Get().Debug().Str("msgCmd", msgCmd).Msg("send msg")

		cmd := exec.Command("sh", "-c", msgCmd)
		var outbuf, errbuf strings.Builder
		cmd.Stdout = &outbuf
		cmd.Stderr = &errbuf
		err := cmd.Run()
		logging.Get().Debug().Msgf("dmsetup send msg cmd run:%s,%s", outbuf.String(), errbuf.String())
		if err != nil {
			// check if device id used
			if d.isDeviceIdConflict(errbuf.String()) {
				curSnapDevId++
				logging.Get().Warn().Int("newDeviceId", curSnapDevId).Msg("allocate new device id")
			}
			return err
		}
		logging.Get().Debug().Msg("dmsetup send msg cmd run ok")
		return nil
	}, retry.Attempts(3))

	if err != nil {
		logging.Get().Err(err).Msg("dmsetup send msg cmd run err")
		return err
	}

	// record device id for defer clean
	d.allocateDeviceId = curSnapDevId

	if err := GetDmSetup().RecordMessage(d.poolDevName, d.allocateDeviceId); err != nil {
		logging.Get().Err(err).Msg("failed to record message")
	}

	return nil
}

// getSnapSize when create snap,we need to notify dmsetup sector numbers (one sector is 512 byte)
// 目前发现基本上所有的image layer被分配的device size都是10GB，不确定devicemapper是怎么分配的(看起来和base device size一致),暂没找到相关文档
// 而且如果创建的snapshot是其他的大小，可能会导致mount时出现supper block错误.
// 因此，我们默认创建snapshot大小为10GB,即20971520个扇区(每个扇区为512byte).同时提供环境变量来修改大小,避免出现超过10G大小的镜像
func (d *DeviceMapper) getSnapSize(image types.ImageInspect) string {
	num := os.Getenv(global.CustomSnapSectorNumberEnv)
	if len(num) != 0 {
		return num
	}
	return global.DefaultDevMapperSnapSectors
}

// createSnap actual create snap cmd
func (d *DeviceMapper) createSnap(image types.ImageInspect) error {
	snapSize := d.getSnapSize(image)
	logging.Get().Debug().Str("snapSize", snapSize).Msg("generate snap size")

	// create snap cmd,not need to retry
	snapCmd := fmt.Sprintf("dmsetup create %s --table \"0 %s thin %s %d\" ", snapName, snapSize, d.poolDevName, d.allocateDeviceId)
	logging.Get().Debug().Str("snapCmd", snapCmd).Msg("generate create snap cmd")

	err := d.commonRunCmd(snapCmd)
	if err != nil {
		return err
	}

	if err := GetDmSetup().RecordSnap(snapName, d.allocateDeviceId); err != nil {
		logging.Get().Err(err).Msg("failed to record snap")
	}

	return nil
}

func (d *DeviceMapper) mountSnap() error {

	mountCmd := fmt.Sprintf("mount %s %s", d.snapDevName, d.snapMountPath)
	logging.Get().Debug().Str("mountCmd", mountCmd).Msg("mount snap")

	err := d.commonRunCmd(mountCmd)
	if err != nil {
		return err
	}

	if err := GetDmSetup().RecordMount(d.snapDevName, d.snapMountPath); err != nil {
		logging.Get().Err(err).Msg("failed to record mount")
	}

	return nil
}

func (d *DeviceMapper) umountSnap() error {

	mountCmd := fmt.Sprintf("umount %s", d.snapDevName)
	logging.Get().Debug().Str("umountCmd", mountCmd).Msg("umount snap")

	return d.commonRunCmd(mountCmd)
}

func (d *DeviceMapper) deleteMessage() error {
	deleteMsgCmd := fmt.Sprintf("dmsetup message %s 0 \" delete %d \"", d.poolDevName, d.allocateDeviceId)
	return d.commonRunCmd(deleteMsgCmd)
}

func (d *DeviceMapper) deleteSnap() error {
	removeSnapCmd := fmt.Sprintf("dmsetup remove %s", snapName)
	return d.commonRunCmd(removeSnapCmd)
}

func (d *DeviceMapper) clearDeviceMapper() error {
	if GetDmSetup().MountRecordExist() {
		if err := d.umountSnap(); err != nil {
			logging.Get().Err(err).Msg("failed to clean: umount snap")
		} else {
			logging.Get().Debug().Msg("clean mount ok")
		}
	}

	if GetDmSetup().SnapRecordExist() {
		if err := d.deleteSnap(); err != nil {
			logging.Get().Err(err).Msg("failed to clean: delete snap")
		} else {
			logging.Get().Debug().Msg("clean snap ok")
		}
	}

	if GetDmSetup().MessageRecordExist() {
		if err := d.deleteMessage(); err != nil {
			logging.Get().Err(err).Msg("failed to clean: delete message")
		} else {
			logging.Get().Debug().Msg("clean message ok")
		}
	}

	logging.Get().Debug().Msg("clean devicemapper finish")
	return nil
}

func (d *DeviceMapper) commonRunCmd(cmdStr string) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(deviceMapperCmdTimeout)*time.Second)
	defer cancel()

	output, err := exec.CommandContext(ctx, "sh", "-c", cmdStr).CombinedOutput()
	if err != nil {
		logging.Get().Err(err).Msgf("cmd run err.%s", string(output))
		return err
	}
	logging.Get().Debug().Str("output", string(output)).Msg("cmd run ok.")
	return nil
}

func NewAnalyzer(analyzer.RegistrableComponentConfig) (analyzer.Analyzer, error) {
	d := &DeviceMapper{
		execFileSet: make(map[string]string),
	}
	return d, nil
}
