package dp

import (
	"bufio"
	"context"
	"fmt"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/dp"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

const (
	testImageName   string = "wade23/deploy:deploytest"
	testImageDigest string = "sha256:26b19629d197c48fecaec99af07442cf24666f485e1a8d18fd045b28f4a8a5ae"

	//testContainerNum         int    = 20 // performance: 7s,1 CPU,100M
	testContainerNum         int    = 1
	testContainerNamePrefix  string = "test-container-"
	injectedPath             string = "/tmp/dp.so"
	injectedFailedMsg        string = "No such file"
	testBlockCmd             string = "sh -c ls" // "docker exec containerID ls" will bypass dp.so,but " sh -c ls" will be ok
	testBlockMsg             string = "Permission deny"
	testImageDigestFile      string = "./data/image_digest.txt"
	testWhitelistFile        string = "./data/whitelist.txt"
	testCheckImageDigestFile string = "./data/check_digest.txt"

	// test exec if block. change hash and shouldPass simultaneously
	testExecHash string = "13C49389" // eg: 13C49389 - pass, 13C49380-block
	testExecPath string = "/bin/ls"
	shouldPass   bool   = true
)

func prepare(t *testing.T) {
	// set env
	os.Setenv("CIA_ENABLED", "1")
	os.Setenv("CIA_IMAGE_REGEXP", "wade23/*")
	//os.Setenv("CIA_IMAGE_REGEXP", "library/*")

	// pull test image
	cmd := exec.Command("docker", "pull", testImageName)
	output, err := cmd.Output()
	if err != nil {
		t.Fatalf("pull test image error:%v,%v", err, output)
	}
}

func createContainers(t *testing.T) {
	runningContainerNum := 0
	for i := 0; i < testContainerNum; i++ {
		containerName := fmt.Sprintf("%s%d", testContainerNamePrefix, i)
		cmdStr := fmt.Sprintf("docker run -d --name %s %s", containerName, testImageName)
		cmd := exec.Command("bash", "-c", cmdStr)
		output, err := cmd.Output()
		if err != nil {
			t.Fatalf("start %s failed:%v", containerName, output)
		} else {
			t.Logf("start %s ok", containerName)
			runningContainerNum++
		}
	}
	t.Logf("running test container num:%d", runningContainerNum)
}

func stopContainer(containerID string) error {
	stopCmdStr := fmt.Sprintf("docker stop %s", containerID)
	stopCmd := exec.Command("bash", "-c", stopCmdStr)
	out, err := stopCmd.Output()
	if err != nil {
		return fmt.Errorf("stop container %s err:%v,%v", containerID, err, string(out))
	}
	return nil
}

func rmContainer(containerID string) error {
	rmCmdStr := fmt.Sprintf("docker rm %s", containerID)
	rmCmd := exec.Command("bash", "-c", rmCmdStr)
	out, err := rmCmd.Output()
	if err != nil {
		return fmt.Errorf("rm container %s err:%v,%v", containerID, err, string(out))
	}
	return nil
}

func cleanTestContainers(t *testing.T) {
	// list all running test container
	cmdStr := fmt.Sprintf("docker ps -a| grep %s|awk '{print $1}'", testContainerNamePrefix)
	cmd := exec.Command("bash", "-c", cmdStr)
	output, err := cmd.Output()
	if err != nil {
		t.Fatalf("clean test container: list running test containers err:%v", err)
	}

	// delete containers
	outputStr := string(output)
	reader := bufio.NewReader(strings.NewReader(outputStr))
	for {
		line, err := reader.ReadString('\n')
		if err != nil && err != io.EOF {
			t.Logf("read err:%v", err)
			break
		}
		if err == io.EOF {
			t.Logf("read end")
			break
		}
		containerID := strings.TrimSuffix(line, "\n")

		// stop container
		err = stopContainer(containerID)
		if err != nil {
			t.Fatalf("stop container err:%v", err)
		}

		// rm container
		err = rmContainer(containerID)
		if err != nil {
			t.Fatalf("rm container err:%v", err)
		}

		t.Logf("rm container %s ok", containerID)
	}

}

func checkInjectedContainers(t *testing.T) {
	// list all running test container
	cmdStr := fmt.Sprintf("docker ps -a| grep %s|awk '{print $1}'", testContainerNamePrefix)
	cmd := exec.Command("bash", "-c", cmdStr)
	output, err := cmd.Output()
	if err != nil {
		t.Fatalf("list running test containers err:%v", err)
	}

	// check every container if injected
	outputStr := string(output)
	reader := bufio.NewReader(strings.NewReader(outputStr))
	for {
		line, err := reader.ReadString('\n')
		if err != nil && err != io.EOF {
			t.Logf("read err:%v", err)
			break
		}
		if err == io.EOF {
			t.Logf("read end")
			break
		}
		containerID := strings.TrimSuffix(line, "\n")

		// check if injected
		checkCmdStr := fmt.Sprintf("docker exec %s ls %s", containerID, injectedPath)
		checkCmd := exec.Command("bash", "-c", checkCmdStr)
		out, err := checkCmd.Output()
		if err != nil {
			t.Fatalf("check inject err:%v", err)
		}
		if strings.Contains(string(out), injectedFailedMsg) {
			t.Fatalf("inject container %s failed,cmd output:%s", containerID, string(out))
		}
		t.Logf("inject container %s ok", containerID)
	}

}

func doDockerExecCmd(containerID, execCmdStr string) ([]byte, error) {
	cmdStr := fmt.Sprintf("docker exec %s %s", containerID, execCmdStr)
	cmd := exec.Command("bash", "-c", cmdStr)
	out, err := cmd.Output()
	return out, err
}

func checkExecPass(t *testing.T) {
	// list all running test container
	cmdStr := fmt.Sprintf("docker ps -a| grep %s|awk '{print $1}'", testContainerNamePrefix)
	cmd := exec.Command("bash", "-c", cmdStr)
	output, err := cmd.Output()
	if err != nil {
		t.Fatalf("list running test containers err:%v", err)
	}

	// do docker cmd in every running test container
	outputStr := string(output)
	reader := bufio.NewReader(strings.NewReader(outputStr))
	for {
		line, err := reader.ReadString('\n')
		if err != nil && err != io.EOF {
			t.Logf("read err:%v", err)
			break
		}
		if err == io.EOF {
			t.Logf("read end")
			break
		}
		containerID := strings.TrimSuffix(line, "\n")

		// check if blocked
		out, err := doDockerExecCmd(containerID, testBlockCmd)
		if err != nil {
			t.Fatalf("test block failed:%v,%v", err, string(out))
		}

		if strings.Contains(string(out), testBlockMsg) {
			if shouldPass {
				t.Fatalf("test container %s should pass,but blocked,cmd output:%s", containerID, string(out))
			} else {
				t.Logf("test container %s blocked,cmd output:%s", containerID, string(out))
			}
		} else {
			t.Logf("test container %s exec:%s pass", containerID, testBlockCmd)
		}
	}
}

func TestInject(t *testing.T) {
	prepare(t)

	// clean last test containers
	cleanTestContainers(t)

	dpService, err := dp.NewDriftAssurance(nil, nil, nil, "", "", nil)
	if err != nil {
		t.Fatalf("new dp service err:%v", err)
	}
	go func() {
		_ = dpService.Start(context.Background())
	}()

	// start test container
	createContainers(t)

	// check injected container
	checkInjectedContainers(t)

	// clean test containers
	cleanTestContainers(t)

	t.Log("inject test end")
}

func TestBlock(t *testing.T) {
	prepare(t)

	// clean last test containers
	cleanTestContainers(t)

	dpService, err := dp.NewDriftAssurance(nil, nil, nil, "", "", nil)
	if err != nil {
		t.Fatalf("new dp service err:%v", err)
	}

	// set test image white list
	cm := dpService.GetConfigManager()
	cm.SetImageExecHash(testImageDigest, testExecHash, testExecPath)

	go func() {
		_ = dpService.Start(context.Background())
	}()

	// start test container
	createContainers(t)

	// test block
	checkExecPass(t)

	// clean test containers
	cleanTestContainers(t)

	t.Log("exec block test end")
}

// TestWhiteList: performance: check hash consume < 1ms with 30k image digest and 1900 exec hashes in one image
func TestWhiteList(t *testing.T) {
	t.Log("start test whiteList")

	dpService, err := dp.NewDriftAssurance(nil, nil, nil, "", "", nil)
	if err != nil {
		t.Fatalf("new dp service err:%v", err)
	}

	// load white list from local file
	cm := dpService.GetConfigManager()
	err = cm.MockWhiteListFromFile(testImageDigestFile, testWhitelistFile)
	if err != nil {
		t.Fatalf("load whitelist file err:%v", err)
	}
	t.Logf("whitelist size:%d", cm.WhiteListSize())

	// load to-check image digest list
	cid, err := os.OpenFile(testCheckImageDigestFile, os.O_RDWR, 0666)
	if err != nil {
		t.Fatalf("open file err:%v", err)
	}
	defer cid.Close()

	checkDigest := make([]string, 0)
	buf2 := bufio.NewReader(cid)
	for {
		line, err := buf2.ReadString('\n')
		line = strings.TrimSpace(line)
		if err != nil {
			if err == io.EOF {
				t.Log("read file end")
				break
			} else {
				t.Fatalf("read file err:%v", err)
			}
		}
		checkDigest = append(checkDigest, line)
	}

	// check and calc time elapsed
	t1 := time.Now()
	for _, v := range checkDigest {
		checkArr := make([]string, 0)
		checkArr = append(checkArr, v)
		existDigest, ok := cm.IsImageDigestsExist(checkArr)
		if !ok {
			t.Fatalf("digest %s not exist", v)
		}
		notInWhiteList, expectHash := cm.IsInWhiteList(existDigest, testExecHash)
		t.Logf("hash %s check result: notInWhiteList %v,misMatch %v,expetcHash %v", testExecHash, notInWhiteList, expectHash)

		t.Logf("image exec hash size:%d", cm.ImageExecHashSize(v))
	}
	t2 := time.Now()
	diff := t2.Sub(t1)
	t.Logf("time elapsed:%v", diff)
}
