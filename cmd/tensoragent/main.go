package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"reflect"
	"syscall"

	log "github.com/sirupsen/logrus"

	ch "gitlab.com/piccolo_su/vegeta/cmd/tensoragent/container-helper"
	kh "gitlab.com/piccolo_su/vegeta/cmd/tensoragent/kubernetes-helper"
)

type SocketEntry struct {
	EventInfo map[string]interface{} `json:"EventInfo"`
	ExtraInfo map[string]interface{} `json:"ExtraInfo"`
}

var cu = ch.NewContainerUtil()
var ku = kh.NewKubernetesUtil()

func main() {
	fmt.Println("Started")
	if len(os.Args) != 2 {
		log.Fatalf("Usage: %s SOCKET_PATH", os.Args[0])
	}
	f, err := os.OpenFile("/data/syscall.json",
		os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Println(err)
	}
	defer f.Close()

	// e := os.Remove(os.Args[1])
	// if e != nil {
	// 	log.Fatal(e)
	// }
	// fmt.Println("Previous socket removed")

	addr, err := net.ResolveUnixAddr("unix", os.Args[1])
	if err != nil {
		fmt.Printf("Failed to resolve: %v\n", err)
		os.Exit(1)
	}

	list, err := net.ListenUnix("unix", addr)
	if err != nil {
		fmt.Printf("failed to listen: %v\n", err)
		os.Exit(1)
	}
	defer list.Close()

	for {
		conn, err := list.AcceptUnix()
		if err != nil {
			fmt.Printf("failed to accept: %v\n", err)
			os.Exit(1)
		}
		go readSyscall(conn, f)
	}
}

func readSyscall(conn *net.UnixConn, f *os.File) {
	defer conn.Close()
	decode := json.NewDecoder(conn)
	for {
		var s SocketEntry
		err := decode.Decode(&s)
		if err != nil {
			fmt.Printf("Error is %v", err)
			return
		}
		pid := int(s.EventInfo["pid"].(float64))
		ptid := int(s.EventInfo["parent_pid"].(float64))
		containerID, err := cu.GetContainerId(pid)
		if err != nil {
			log.Printf("Problem getting container ID: %v", err)
		}
		if containerID == -1 {
			containerID, err = cu.GetContainerId(ptid)
			if err != nil {
				log.Printf("Problem getting container ID: %v", err)
			}
		}
		if pid > 0 {
			info, err := ku.LookupPod(containerID, pid, s.ExtraInfo["syscall"].(string))
			if err != nil {
				log.Printf("Problem getting pod ID: %v", err)
			} else {
				if info.DockerPID <= 0 {
					info, err = ku.LookupPod(containerID, ptid, s.ExtraInfo["syscall"].(string))
					if err != nil {
						log.Printf("Problem getting pod ID: %v", err)
					}
				}
				if info.DockerPID <= 0 {
					log.Println("Host syscall")
				} else {
					out := map[string]interface{}{}
					v := reflect.ValueOf(*info)
					typeOfS := v.Type()
					for i := 0; i < v.NumField(); i++ {
						out[typeOfS.Field(i).Name] = v.Field(i).Interface()
					}
					for key, element := range s.ExtraInfo {
						out[key] = element
					}
					for key, element := range s.EventInfo {
						out[key] = element
					}
					if s.ExtraInfo["syscall"] == "openat" {
						out["openat__write"] = false
						if uint64(s.ExtraInfo["openat__mode"].(float64))&syscall.O_WRONLY > 0 {
							out["openat__write"] = true
						}
					}
					if s.ExtraInfo["syscall"] == "open" {
						out["open__write"] = false
						if uint64(s.ExtraInfo["open__mode"].(float64))&syscall.O_WRONLY > 0 {
							out["open__write"] = true
						}
					}

					jsonStr, _ := json.Marshal(out)
					if _, err := f.WriteString(string(jsonStr) + "\n"); err != nil {
						log.Println(err)
					}
					log.Printf("Relevant information: %+v\n", out)
				}
			}
		} else if pid == 0 {
			log.Println("Host syscall")
		} else {
			log.Println("Root process has died")
		}
	}
}
