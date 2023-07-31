package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/container"
	_ "gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/container/containerd"
	_ "gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/container/crio"
	_ "gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/container/docker"
)

var (
	countTargets     = map[string]int{}
	rt               container.Runtime
	supportOSTargets = []string{
		"ubuntu-22.04",
		"ubuntu-20.04",
		"ubuntu-18.04",
		"ubuntu-16.04",
		"debian-11",
		"debian-10",
		"debian-9",
		"centos-8",
		"centos-7",
		"rhel-8.5",
		"rhel-8.4",
		"rhel-6.5",
		"photon-4.0",
		"photon-3.0",
		"photon-2.0",
		"photon-1.0",
		"opensuse-42.3",
	}
)

func getOSTargetFromFile(path string) (string, error) {
	targetStr := ""
	osName := ""
	osVersion := ""
	f, err := os.Open(path)
	if err != nil {
		fmt.Printf("Failed to read file %s\n", path)
		return "", err
	}
	defer f.Close()
	br := bufio.NewReader(f)
	for {
		line, _, c := br.ReadLine()
		if c == io.EOF {
			break
		}
		lineStr := string(line)
		kv := strings.Split(lineStr, "=")
		if len(kv) != 2 {
			continue
		}
		if kv[0] == "ID" {
			osName = strings.Trim(strings.Trim(strings.Trim(kv[1], "\n"), " "), "\"")
		}
		if kv[0] == "VERSION_ID" {
			osVersion = strings.Trim(strings.Trim(strings.Trim(kv[1], "\n"), " "), "\"")
		}
	}
	targetStr = osName + "-" + osVersion
	return strings.ToLower(targetStr), nil

}

func main() {
	fmt.Println("start")
	// uri := os.Getenv("DOCKER_SOCKET_ADDR")
	// if len(uri) == 0 {
	// 	uri = "unix:///var/run/docker.sock"
	// }

	rtt, err := container.Open(container.RuntimeConfig{Type: "docker"})
	if err != nil {
		fmt.Println(err)
		return
	}
	rt = rtt

	runningContainers, err := rt.ListRunningContainers()
	for _, c := range runningContainers {
		cm, err := rt.GetContainerMeta(c.Namespace, c.ID)
		if err != nil {
			fmt.Printf("%v\n", err)
			// continue
		}
		fmt.Printf("%+v \n", cm)
		target := ""
		if _, err := os.Stat("/host"); err == nil {
			target, err = getOSTargetFromFile(fmt.Sprintf("/host/proc/%d/root/etc/os-release", cm.ProcessID))
		} else {
			target, err = getOSTargetFromFile(fmt.Sprintf("/proc/%d/root/etc/os-release", cm.ProcessID))
		}
		if err != nil {
			fmt.Printf("%v \n", err)
			fmt.Println()
			continue
		}
		countTargets[target]++
	}
	unSupports := ""
	supportOSCount := 0
	total := 0
	for k, v := range countTargets {
		c := false
		total += v
		for _, supportOS := range supportOSTargets {
			if k == supportOS {
				fmt.Println(k, v)
				supportOSCount += v
				c = true
				break
			}
		}
		if c {
			continue
		}
		unSupports += fmt.Sprintf("%s : %d\n", k, v)
	}
	fmt.Printf("support rate: %v, support: %d, total: %d\n", float32(supportOSCount)/float32(total), supportOSCount, total)
	fmt.Println("unSupportOS:")
	fmt.Println(unSupports)
}
