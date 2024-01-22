package scannerUtils

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestParseImageName(t *testing.T) {
	im := "docker.io/573320328/liuqianli:v9"
	host, repo, tag := ParseImageName(im)
	fmt.Println(host)
	fmt.Println(repo)
	fmt.Println(tag)
}

func TestGetSha256Digest(t *testing.T) {
	// im := "docker.io/573320328/liuqianli@sha256:c57b291c4f0f9b4b17cf56a4628b25c323a811d1784a89f66b1379bbaeb5599d"
	im := "sha256:c57b291c4f0f9b4b17cf56a4628b25c323a811d1784a89f66b1379bbaeb5599d"
	digest := GetSha256Digest(im)
	fmt.Println(digest)
}

func TestUnzipDBFile(t *testing.T) {
	des := "/Users/liuqianli/Documents/vuln/"
	file := "/Users/liuqianli/Documents/vulndb_20231203.zip"
	err := UnzipDBFile(file, des, "tanzhen2020scanner")
	if err != nil {
		fmt.Println(err.Error())
	}
}

func BenchmarkExtractTar(b *testing.B) {
	des := fmt.Sprintf("/Users/liuqianli/Documents/hello")
	file := "/Users/liuqianli/Documents/layer.tar"

	for i := 1; i < b.N; i++ {
		err := ExtractTar(file, des)
		if err != nil {
			fmt.Println("error is ", err)
		}
	}
}

func TestExtractTar(b *testing.T) {
	des := fmt.Sprintf("/Users/liuqianli/Documents/hello")
	file := "/Users/liuqianli/Documents/bolb.tar.gz"
	_ = os.RemoveAll(des)
	err := ExtractDockerTar3(file, des)
	if err != nil {
		fmt.Println("error is ", err)
	}
}

func TestExtractDockerTar(b *testing.T) {
	des := fmt.Sprintf("/Users/liuqianli/Documents/hello")
	file := "/Users/liuqianli/Documents/layer.tar"
	filepath.Clean(des)
	start := time.Now().UnixMilli()
	err := ExtractDockerTar(file, des)
	if err != nil {
		fmt.Println("error is ", err)
	}
	fmt.Println(time.Now().UnixMilli() - start)
}

func BenchmarkExtractDockerTar(b *testing.B) {
	des := fmt.Sprintf("/Users/liuqianli/Documents/hello")
	file := "/Users/liuqianli/Documents/layer.tar"

	for i := 1; i < b.N; i++ {
		err := ExtractDockerTar(file, des)
		if err != nil {
			fmt.Println("error is ", err)
		}
	}
}
