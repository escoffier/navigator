package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/huaweicloud/huaweicloud-sdk-go-obs/obs"
	scannerUtils "gitlab.com/piccolo_su/vegeta/cmd/scanner/utils"
)

func NewObsApi(opts ...Option) (*Obs, error) {
	c := &Obs{}
	for _, opt := range opts {
		opt(c)
	}

	if c.endpoint == "" {
		// obs.cn-east-3.myhuaweicloud.com
		c.endpoint = fmt.Sprintf("obs.%s.myhuaweicloud.com", c.region)
	}

	if c.bucket == "" {
		c.bucket = fmt.Sprintf("cspm-%s", c.region)
	}
	obsClient, err := obs.New(c.secretId, c.secretKey, c.endpoint)
	if err != nil {
		e1 := fmt.Errorf("create obsClient error, errMsg: %s", err.Error())
		return nil, e1
	}
	c.client = obsClient

	return c, nil
}

type Obs struct {
	secretId  string
	secretKey string
	region    string
	endpoint  string
	bucket    string // cspm-ap-chengdu
	client    *obs.ObsClient
	log       *scannerUtils.LogEvent
}

type Option func(c *Obs)

func WithSecret(secretId, secretKey string) Option {
	return func(c *Obs) {
		c.secretId = secretId
		c.secretKey = secretKey
	}
}

func WithRegion(region string) Option {
	return func(c *Obs) {
		c.region = region
	}
}

func WithEndpoint(endpoint string) Option {
	return func(c *Obs) {
		c.endpoint = endpoint
	}
}

func WithBucket(bucket string) Option {
	return func(c *Obs) {
		c.bucket = bucket
	}
}

// GetObjectContent downloads object content via signed URL
func (o *Obs) GetObjectContent(ctx context.Context, key string) ([]byte, error) {

	input := &obs.GetObjectInput{
		GetObjectMetadataInput: obs.GetObjectMetadataInput{
			Bucket: o.bucket,
			Key:    key,
		},
	}

	object, err := o.client.GetObject(input)
	if err != nil {
		return nil, err
	}

	defer object.Body.Close()

	body, err := io.ReadAll(object.Body)
	if err != nil {
		return nil, err
	}

	return body, nil
}

func (o *Obs) GetAllObj(ctx context.Context) ([]string, error) {
	var (
		dirs   []string
		marker string
	)

	for {
		input := &obs.ListObjectsInput{Bucket: o.bucket, Marker: marker}

		output, err := o.client.ListObjects(input)
		if err != nil {
			return nil, err
		}

		for _, obj := range output.Contents {
			key := obj.Key
			if key == "" {
				break
			}
			dirs = append(dirs, key)
		}
		marker = output.NextMarker
		if marker == "" {
			break
		}
	}
	sort.Strings(dirs)
	return dirs, nil
}

// CreateDirectory creates a directory (folder) in OBS bucket
// In OBS, directories are simulated by creating empty objects with keys ending in "/"
func (o *Obs) CreateDirectory(ctx context.Context, dirPath string) error {
	// Ensure the directory path ends with "/"
	if !strings.HasSuffix(dirPath, "/") {
		dirPath = dirPath + "/"
	}

	input := &obs.PutObjectInput{
		PutObjectBasicInput: obs.PutObjectBasicInput{
			ObjectOperationInput: obs.ObjectOperationInput{
				Bucket: o.bucket,
				Key:    dirPath,
			},
		},
		Body: strings.NewReader(""),
	}

	_, err := o.client.PutObject(input)
	if err != nil {
		return fmt.Errorf("create directory %s error: %s", dirPath, err.Error())
	}

	return nil
}

// UploadFile uploads a file to the specified directory in OBS bucket
func (o *Obs) UploadFile(ctx context.Context, dirPath, fileName, localFilePath string) error {
	// Ensure the directory path ends with "/"
	if !strings.HasSuffix(dirPath, "/") {
		dirPath = dirPath + "/"
	}

	// Construct the full object key
	objectKey := dirPath + fileName

	// Open the local file
	file, err := os.Open(localFilePath)
	if err != nil {
		return fmt.Errorf("open local file %s error: %s", localFilePath, err.Error())
	}
	defer file.Close()

	// Get file info for content length
	fileInfo, err := file.Stat()
	if err != nil {
		return fmt.Errorf("get file info %s error: %s", localFilePath, err.Error())
	}

	input := &obs.PutObjectInput{
		PutObjectBasicInput: obs.PutObjectBasicInput{
			ObjectOperationInput: obs.ObjectOperationInput{
				Bucket: o.bucket,
				Key:    objectKey,
			},
			ContentLength: fileInfo.Size(),
		},
		Body: file,
	}

	_, err = o.client.PutObject(input)
	if err != nil {
		return fmt.Errorf("upload file %s to %s error: %s", localFilePath, objectKey, err.Error())
	}

	return nil
}
