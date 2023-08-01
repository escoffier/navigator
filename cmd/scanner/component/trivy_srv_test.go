package component

import (
	"context"
	"fmt"
	"testing"

	"github.com/go-redis/redis/v8"
)

func TestScan(t *testing.T) {
	client := redis.NewClient(&redis.Options{
		Addr: ":6379",
	})
	trivyDbPath := "/Users/liuqianli/Documents/workfile/trivy/trivy.db"

	server, err := NewTrivyServer(*client, trivyDbPath)
	if err != nil {
		fmt.Println("NewTrivyServer", err.Error())
		return
	}
	scan, err := server.Scan(context.Background(), "573320328/tensecbclinux:basecentos")

	if err != nil {
		fmt.Println("scan error", err.Error())
		return
	}
	fmt.Println("Scna result is ", scan.Results)

}
