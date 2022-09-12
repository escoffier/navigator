package dp

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"runtime/debug"
	"strings"
	"syscall"
	"time"

	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/container"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/degrade"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/nodeinfo"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"gitlab.com/security-rd/go-pkg/logging"
	"gitlab.com/security-rd/go-pkg/mq"
	"gitlab.com/security-rd/go-pkg/sdk/palace"
)

type ExecJudge struct {
	cm            *ConfigManager
	rt            container.Runtime
	SocketPath    string
	mq            mq.Writer
	npw           *nodeinfo.NodePodsWatcher
	podResInfo    *nodeinfo.PodResInfo
	clusterName   string
	palaceHandler *palace.Palace
}

const (
	contentDelimiter   string = "|" // msg format: time containerID cmd exec-path file-hash
	defaultDelimiter   byte   = '\n'
	receiveTimeout     int    = 3
	defaultJudgeSocket string = degrade.DriftPath + "/mnt/judge.sock"
	resultPass         string = "pass"
	resultBlock        string = "block"
)

func (ej *ExecJudge) Start() error {
	logging.Get().Info().Msg("judge start")

	// remove original socket file to avoid rebind err
	unixSockFile := unixSockFileFromAddr(ej.SocketPath)
	if err := os.RemoveAll(unixSockFile); err != nil {
		return fmt.Errorf("remove original socket err:%v,%s", err, unixSockFile)
	}

	// create a unix socket server and listen
	unixAddr, err := net.ResolveUnixAddr("unix", ej.SocketPath)
	if err != nil {
		return fmt.Errorf("judge resolve unix socket path err:%v", err)
	}

	unixListener, err := net.ListenUnix("unix", unixAddr)
	if err != nil {
		return fmt.Errorf("judge listen unix socket err:%v", err)
	}
	defer unixListener.Close()

	if err = os.Chmod(ej.SocketPath, os.FileMode(0x0777)); err != nil {
		return fmt.Errorf("socket file chmod fail err:%v", err)
	}

	for {
		logging.Get().Trace().Msg("wait unix socket request")

		unixConn, err := unixListener.AcceptUnix()
		if err != nil {
			logging.Get().Err(err).Msg("judge accept unix socket request err")
			time.Sleep(2 * time.Second)
			continue
		}

		logging.Get().Trace().Msg("judge receive request")

		// every exec command will create a new conn
		go func(conn *net.UnixConn) {
			defer func() {
				logging.Get().Trace().Msg("judge close conn")
				_ = conn.Close()
			}()
			defer func() {
				if r := recover(); r != nil {
					logging.Get().Error().Msgf("judge do request panic: %v.stack:%s", r, debug.Stack())
				}
			}()
			_ = ej.doRequest(conn, 0)
		}(unixConn)
	}

	return nil
}

func (ej *ExecJudge) readStringWithTimeout(ctx context.Context, r *bufio.Reader) (string, error) {
	tmpCtx, cancel := context.WithTimeout(ctx, time.Duration(receiveTimeout)*time.Second)
	defer cancel()

	msgChan := make(chan string, 1)
	errChan := make(chan error, 1)
	go func() {
		msg, err := r.ReadString(defaultDelimiter)
		if err != nil {
			errChan <- err
			return
		}
		msgChan <- msg
	}()
	select {
	case err := <-errChan:
		return "", err
	case msg := <-msgChan:
		return msg, nil
	case <-tmpCtx.Done():
		return "", fmt.Errorf("read unix conn data timeout:%v", ctx.Err())
	}
}

type containerPolicy struct {
	uuid         uint32
	namespace    string
	cluster      string
	resourceKind string
	resourceName string
	podFullName  string
}

func getContainerPolicyInfo(podUID string, npw *nodeinfo.NodePodsWatcher, podResInfo *nodeinfo.PodResInfo) (containerPolicy, error) {
	containerPolicyInfo := containerPolicy{}
	// get pod info by containerID
	podInfo, err := npw.GetPodByUID(podUID)
	if err != nil {
		logging.Get().Error().Err(err).Msg("get pod info fail")
		return containerPolicyInfo, err
	}
	logging.Get().Trace().Msgf("generateEvent: %v", podInfo)
	containerPolicyInfo.namespace = podInfo.Namespace
	containerPolicyInfo.cluster = podInfo.ClusterKey
	containerPolicyInfo.podFullName = podInfo.Name

	resKeyType, ok := podResInfo.GetPod(podInfo.Namespace, podInfo.Name)
	if !ok {
		logging.Get().Error().Msgf("get pod res info fail, pod:%s/%s", podInfo.Namespace, podInfo.Name)
		return containerPolicyInfo, errors.New("get pod res info fail")
	}

	containerPolicyInfo.resourceKind = resKeyType.Kind
	containerPolicyInfo.resourceName = resKeyType.Name
	containerPolicyInfo.uuid = util.GenerateUUID(containerPolicyInfo.cluster, containerPolicyInfo.namespace,
		containerPolicyInfo.resourceKind, containerPolicyInfo.resourceName)
	return containerPolicyInfo, nil
}

var (
	enforceBinaryList = []string{"sh", "bash", "python", "java", "php", "dash"}
)

func (ej *ExecJudge) doRequest(conn *net.UnixConn, uuid uint64) error {
	logging.Get().Trace().Uint64("uuid", uuid).Msg("start do request")

	r := bufio.NewReader(conn)
	// use for-loop to support multi msg,
	// but normally we should only recv one msg
	for {
		msg, err := ej.readStringWithTimeout(context.Background(), r)
		if err != nil && err != io.EOF {
			logging.Get().Err(err).Uint64("uuid", uuid).Msg("read unix conn data err")
			return err
		}
		if err == io.EOF {
			// client close connection
			logging.Get().Trace().Uint64("uuid", uuid).Msg("read eof,client close conn")
			return nil
		}

		// get containerID and file hash
		logging.Get().Trace().Uint64("uuid", uuid).Str("msg", msg).Msg("receive msg content")
		arr := strings.Split(msg, contentDelimiter)
		if len(arr) != 5 {
			logging.Get().Error().Uint64("uuid", uuid).Str("content", msg).Msg("message format err")
			_ = ej.Response(conn, resultPass, "", "")
			continue
		}
		containerID := arr[1]
		syscall := arr[2]
		filePath := arr[3]
		fileHash := strings.TrimSuffix(arr[4], "\n")
		crc32Expected := ""

		logging.Get().Info().Uint64("uuid", uuid).Str("containerID", containerID).Str("syscall", syscall).Str("filePath", filePath).Str("fileHash", fileHash).Msg("receive msg content")
		// get image info by containerID
		containMeta, err := ej.rt.GetContainerMeta(containerID)
		if err != nil {
			logging.Get().Err(err).Uint64("uuid", uuid).Str("containerID", containerID).Msg("not found container image info")
			_ = ej.Response(conn, resultPass, containerID, fileHash)
			continue
		}
		logging.Get().Trace().Interface("Meta", containMeta).Msg("container meta info")

		skip := false
		// check whitelist state
		for _, digest := range containMeta.ImageDigest {
			state, exist := ej.cm.GetWhiteListState(digest)
			if state != WhiteListReady && exist {
				logging.Get().Warn().Msgf("whitelist not ready imageDigest: %s\n", digest)
				skip = true
				break
			}
		}

		if skip {
			logging.Get().Warn().Msg("white list not ready skip check")
			_ = ej.Response(conn, resultPass, containerID, fileHash)
			continue
		}

		// check file hash is in white list
		cPodInfo, err := getContainerPolicyInfo(containMeta.PodUID, ej.npw, ej.podResInfo)
		if err != nil {
			logging.Get().Err(err).Uint64("uuid", uuid).Str("containerID", containerID).Msg("get container info err")
			_ = ej.Response(conn, resultPass, containerID, fileHash)
			continue
		}

		logging.Get().Trace().Msgf("containerPolicyInfo: %+v", cPodInfo)

		polic, ok := ej.cm.GetPolicyByResourceUUID(cPodInfo.uuid)

		logging.Get().Info().Msgf("plic: %+v ok? %v", polic, ok)
		if !ok || polic.Enable == 0 {
			logging.Get().Warn().Uint64("uuid", uuid).Str("containerID", containerID).Msg("skip check file hash")
			_ = ej.Response(conn, resultPass, containerID, fileHash)
			continue
		}
		if polic.Mode != 1 && polic.Mode != 2 {
			_ = ej.Response(conn, resultPass, containerID, fileHash)
			continue
		}
		needBlock := polic.Mode == 2

		stopCheck := false
		if enforceBlock := os.Getenv("ENFORCE_BLOCK"); enforceBlock == "true" {
			tmpBinaryNameList := strings.Split(filePath, "/")
			binaryName := tmpBinaryNameList[len(tmpBinaryNameList)-1]
			for _, b := range enforceBinaryList {
				if strings.HasPrefix(binaryName, b) {
					stopCheck = true
					break
				}
			}

		}
		if stopCheck {
			action := ""
			if needBlock {
				_ = ej.Response(conn, resultBlock, containerID, fileHash)
				action = "block"
			} else {
				_ = ej.Response(conn, resultPass, containerID, fileHash)
				action = "pass"
			}
			if err != nil {
				logging.Get().Err(err).Uint64("uuid", uuid).Str("containerID", containerID).Msg("response err")
			}

			eventArgs := &EventArg{
				ClusterID:     cPodInfo.cluster,
				Cluster:       ej.clusterName,
				Namespace:     cPodInfo.namespace,
				PodName:       cPodInfo.podFullName,
				PodUID:        containMeta.PodUID,
				ContainerID:   containerID,
				ContainerName: containMeta.Name,
				FilePath:      filePath,
				Syscall:       syscall,
				crc32Expected: crc32Expected,
				crc32Actual:   fileHash,
				Action:        action,
				ImageRepoTags: strings.Join(containMeta.ImageRepoTags, "\n"),
				reason:        "file not in white list",
			}

			ruleKey, scopes, signalContext := genPalaceSignalParams(eventArgs, cPodInfo, "DriftPrevention", "Drift Prevention")
			err := ej.palaceHandler.SendSignal(ruleKey, scopes, signalContext)
			if err != nil {
				logging.Get().Err(err).Str("args", fmt.Sprintf("%+v", eventArgs)).Msg("DriftPrevention send signal to palace fails!")
			}
			continue
		}

		existDigest, ok := ej.cm.IsImageDigestsExist(containMeta.ImageDigest)
		if !ok {
			logging.Get().Error().Uint64("uuid", uuid).Str("containerID", containerID).Str("image digest", strings.Join(containMeta.ImageDigest, " ")).Msg("not found container image digest white list")
			if needBlock {
				_ = ej.Response(conn, resultBlock, containerID, fileHash)
			} else {
				_ = ej.Response(conn, resultPass, containerID, fileHash)
			}
			continue
		}

		notInWhitelistFlag, crc32Expected := ej.cm.IsInWhiteList(existDigest, filePath)
		fileHashMismatchFlag := crc32Expected != fileHash
		logging.Get().Trace().Uint64("uuid", uuid).Str("containerID", containerID).Str("filePath", filePath).Str("fileHash", fileHash).Str("crc32Expected", crc32Expected).Msg("check file hash")
		if notInWhitelistFlag || fileHashMismatchFlag {
			action := ""
			if needBlock {
				_ = ej.Response(conn, resultBlock, containerID, fileHash)
				action = "block"
			} else {
				_ = ej.Response(conn, resultPass, containerID, fileHash)
				action = "pass"
			}
			if err != nil {
				logging.Get().Err(err).Uint64("uuid", uuid).Str("containerID", containerID).Msg("response err")
			}

			eventArgs := &EventArg{
				ClusterID:     cPodInfo.cluster,
				Cluster:       ej.clusterName,
				Namespace:     cPodInfo.namespace,
				PodName:       cPodInfo.podFullName,
				PodUID:        containMeta.PodUID,
				ContainerID:   containerID,
				ContainerName: containMeta.Name,
				FilePath:      filePath,
				Syscall:       syscall,
				crc32Expected: crc32Expected,
				crc32Actual:   fileHash,
				Action:        action,
				ImageRepoTags: strings.Join(containMeta.ImageRepoTags, "\n"),
				reason:        "",
			}
			if notInWhitelistFlag {
				eventArgs.reason = "file not in white list"
			} else if fileHashMismatchFlag {
				eventArgs.reason = "file hash mismatch"
			}

			ruleKey, scopes, signalContext := genPalaceSignalParams(eventArgs, cPodInfo, "DriftPrevention", "Drift Prevention")
			err := ej.palaceHandler.SendSignal(ruleKey, scopes, signalContext)
			if err != nil {
				logging.Get().Err(err).Str("args", fmt.Sprintf("%+v", eventArgs)).Msg("DriftPrevention send signal to palace fails!")
			}
			continue
		} else {
			_ = ej.Response(conn, resultPass, containerID, fileHash)
		}
	}

	return nil
}

func (ej *ExecJudge) Response(conn *net.UnixConn, result, containerID, fileHash string) error {
	rsp := result + "\n"
	_, err := conn.Write([]byte(rsp))
	if err != nil {
		errMsg := ""
		// some command (eg:'docker exec -it containerID bash') will generate two exec cmd(eg: '/usr/bin/groups' and '/usr/bin/dircolors')
		// the process will exit when one exec cmd was blocked that will close unix socket connection
		// the response message of second exec cmd will result a broken pipe error
		if errors.Is(err, syscall.EPIPE) {
			errMsg = "client close conn"
		}
		logging.Get().
			Err(err).
			Str("container", containerID).
			Str("result", result).
			Str("fileHash", fileHash).
			Msgf("judge response failed %s", errMsg)
		return err
	}
	logging.Get().
		Info().
		Str("container", containerID).
		Str("result", result).
		Str("fileHash", fileHash).
		Msg("judge finish")

	return nil
}

func NewExecJudge(socketPath string, cm *ConfigManager, rt container.Runtime, podWatcher *nodeinfo.NodePodsWatcher, podResInfo *nodeinfo.PodResInfo, mq mq.Writer, clusterName string, palaceHandler *palace.Palace) (*ExecJudge, error) {
	var path string
	if len(strings.TrimSpace(socketPath)) == 0 {
		path = defaultJudgeSocket
	}

	ej := &ExecJudge{
		SocketPath:    path,
		cm:            cm,
		rt:            rt,
		npw:           podWatcher,
		podResInfo:    podResInfo,
		mq:            mq,
		clusterName:   clusterName,
		palaceHandler: palaceHandler,
	}
	return ej, nil
}
