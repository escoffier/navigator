package containerd

import (
	"context"
	"fmt"
	"testing"
)

func TestNewDriver(t *testing.T) {
	dr, err := NewDriver(DriverConfig{})
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	// ubunt := "docker.io/library/ubuntu:latest"
	ubunt := "docker.io/573320328/liuqianli:v9"
	ctx := context.Background()
	images, err := dr.ListImages(ctx)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	for i := range images {
		image, err := dr.InspectImage(ctx, images[i].Namespace, images[i].ID)
		if err != nil {
			fmt.Println(err.Error())
			return
		}
		fmt.Println("image is ", image)
	}

	ins, err := dr.InspectImage(ctx, "default", ubunt)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	fmt.Println(ins, ins)
	history, err := dr.ImageLayers(ctx, "default", ubunt)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	fmt.Println(history)
}
