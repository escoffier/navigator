package devicemapper

import (
	"context"
	"fmt"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/global"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"gitlab.com/security-rd/go-pkg/logging"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

var (
	instance *Dmsetup
)

// Dmsetup define dmsetup operation
// todo: move all dmsetup cmd to here
type Dmsetup struct {
	WorkingDir        string
	MessageRecordFile string
	SnapRecordFile    string
	MountRecordFile   string
}

func init() {
	w := filepath.Join(global.GetDpRealWorkingDir(), global.DmSetupDir)
	if err := os.MkdirAll(w, os.ModePerm); err != nil {
		if !os.IsExist(err) {
			logging.Get().Err(err).Msg("failed to create dmsetup working dir")
		}
	}

	instance = &Dmsetup{
		WorkingDir:        w,
		MessageRecordFile: filepath.Join(w, "message-record"),
		SnapRecordFile:    filepath.Join(w, "snap-record"),
		MountRecordFile:   filepath.Join(w, "mount-record"),
	}
}

func GetDmSetup() *Dmsetup {
	return instance
}

func (d *Dmsetup) RecordMessage(poolDevName string, curSnapDevId int) error {
	content := fmt.Sprintf("%s-%d", poolDevName, curSnapDevId)
	return os.WriteFile(d.MessageRecordFile, []byte(content), os.ModePerm)
}

func (d *Dmsetup) RecordSnap(snapName string, allocateDevId int) error {
	content := fmt.Sprintf("%s-%d", snapName, allocateDevId)
	return os.WriteFile(d.SnapRecordFile, []byte(content), os.ModePerm)
}

func (d *Dmsetup) RecordMount(snapDevName, mountPath string) error {
	content := fmt.Sprintf("%s-%s", snapDevName, mountPath)
	return os.WriteFile(d.MountRecordFile, []byte(content), os.ModePerm)
}

func (d *Dmsetup) MessageRecordExist() bool {
	return util.FileExists(d.MessageRecordFile)
}

func (d *Dmsetup) SnapRecordExist() bool {
	return util.FileExists(d.SnapRecordFile)
}

func (d *Dmsetup) MountRecordExist() bool {
	return util.FileExists(d.MountRecordFile)
}

func (d *Dmsetup) UmountByFile() error {
	data, err := os.ReadFile(d.MountRecordFile)
	if err != nil {
		logging.Get().Err(err).Msg("failed to read mount file")
		return err
	}
	arr := strings.Split(string(data), "-")
	if len(arr) < 2 {
		logging.Get().Error().Msg("mount record file format err")
		return fmt.Errorf("mount record file format err")
	}

	umountCmd := fmt.Sprintf("umount %s", arr[0])
	logging.Get().Debug().Str("umountCmd", umountCmd).Msg("umount snap")
	_, err = d.CommonRunCmd(umountCmd)

	return err
}

func (d *Dmsetup) RemoveSnap() error {
	data, err := os.ReadFile(d.SnapRecordFile)
	if err != nil {
		logging.Get().Err(err).Msg("failed to read snap file")
		return err
	}
	arr := strings.Split(string(data), "-")
	if len(arr) < 2 {
		logging.Get().Error().Msg("snap record file format err")
		return fmt.Errorf("snap record file format err")
	}

	removeSnapCmd := fmt.Sprintf("dmsetup remove %s", arr[0])
	logging.Get().Debug().Str("removeSnapCmd", removeSnapCmd).Msg("remove snap")
	_, err = d.CommonRunCmd(removeSnapCmd)
	return err
}

func (d *Dmsetup) DeleteMessage() error {
	data, err := os.ReadFile(d.MessageRecordFile)
	if err != nil {
		logging.Get().Err(err).Msg("failed to read message record file")
		return err
	}
	arr := strings.Split(string(data), "-")
	if len(arr) < 2 {
		logging.Get().Error().Msg("message record file format err")
		return fmt.Errorf("message record file format err")
	}

	deleteMsgCmd := fmt.Sprintf("dmsetup message %s 0 \" delete %s \"", arr[0], arr[1])
	logging.Get().Debug().Str("deleteMsgCmd", deleteMsgCmd).Msg("delete message")
	_, err = d.CommonRunCmd(deleteMsgCmd)
	return err
}

func (d *Dmsetup) ClearFromFile() error {
	if d.MountRecordExist() {
		_ = d.UmountByFile()
	}

	if d.SnapRecordExist() {
		_ = d.RemoveSnap()
	}

	if d.MessageRecordExist() {
		_ = d.DeleteMessage()
	}

	logging.Get().Debug().Msg("clear dmsetup finished")
	return nil
}

func (d *Dmsetup) CommonRunCmd(cmdStr string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(deviceMapperCmdTimeout)*time.Second)
	defer cancel()

	output, err := exec.CommandContext(ctx, "sh", "-c", cmdStr).CombinedOutput()
	if err != nil {
		logging.Get().Err(err).Msgf("cmd run err.%s", string(output))
		return output, err
	}
	logging.Get().Debug().Str("output", string(output)).Msg("cmd run ok.")
	return output, nil
}
