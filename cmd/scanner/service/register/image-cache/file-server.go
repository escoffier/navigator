package imagecache

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"gitlab.com/security-rd/go-pkg/logging"
)

const (
	FileServerRootDir = "layerManage"
	LayerFileName     = "layer.tar"
	FileServerCache   = "FileServerCache"
	ManifestsDir      = "manifests"
	DataDir           = "data"
)

type FileServer struct {
	ctx            context.Context
	rootPath       string
	port           int
	serverIP       string
	externalIP     string
	server         *http.Server
	serverRootPath string // actual server root path: /tmp/xxx
}

func NewFileServer(ctx context.Context, rootPath, externalIP, serverIP string, port int) (*FileServer, error) {
	fs := &FileServer{
		ctx:        ctx,
		rootPath:   rootPath,
		port:       port,
		serverIP:   serverIP,
		externalIP: externalIP,
	}

	return fs, nil
}

func (fs *FileServer) CreateHTTPRootDir() error {
	if _, err := os.Stat(FileServerCache); os.IsNotExist(err) {
		err := os.Mkdir(FileServerCache, 0777)
		if err != nil {
			return err
		}
	}

	fs.serverRootPath = filepath.Join(FileServerCache, FileServerRootDir)
	if _, err := os.Stat(fs.serverRootPath); os.IsNotExist(err) {
		err := os.MkdirAll(fs.serverRootPath, os.ModePerm)
		if err != nil {
			return err
		}
	}

	dataPath := filepath.Join(fs.serverRootPath, DataDir)
	if _, err := os.Stat(dataPath); os.IsNotExist(err) {
		err := os.MkdirAll(dataPath, os.ModePerm)
		if err != nil {
			return err
		}
	}

	manifestPath := filepath.Join(fs.serverRootPath, ManifestsDir)
	if _, err := os.Stat(manifestPath); os.IsNotExist(err) {
		err := os.MkdirAll(manifestPath, os.ModePerm)
		if err != nil {
			return err
		}
	}

	return nil
}

func (fs *FileServer) CreateFileServer() error {
	mux := http.NewServeMux()
	mux.Handle("/", http.FileServer(http.Dir(fs.serverRootPath)))
	fs.server = &http.Server{
		// listen on all IPs
		Addr:    fmt.Sprintf("%s:%d", fs.serverIP, fs.port),
		Handler: mux,
	}
	return nil
}

func (fs *FileServer) StartFileServer() error {
	go func() {
		if err := fs.server.ListenAndServe(); err != nil {
			logging.Get().Err(err).Msg("file server start err")
		}
	}()
	// It takes some time to open the port, just to be sure we wait a bit
	time.Sleep(100 * time.Millisecond)
	logging.Get().Info().Msgf("image cache external file server listen on port %d", fs.port)
	return nil
}

func (fs *FileServer) StopFileServer() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := fs.server.Shutdown(ctx); err != nil {
		logging.Get().Error().
			Err(err).
			Msg("error in shutting down HTTP server")
		return err
	}
	return nil
}

func (fs *FileServer) Run(ctx context.Context) error {
	if err := fs.CreateHTTPRootDir(); err != nil {
		return err
	}

	if err := fs.CreateFileServer(); err != nil {
		return err
	}

	if err := fs.StartFileServer(); err != nil {
		return err
	}

	return nil
}

func (fs *FileServer) SaveFile(digest string, r io.ReadCloser) (string, error) {
	fp := filepath.Join("FileServerCache/", fs.rootPath, "data/", digest)
	if _, err := os.Stat(fp); os.IsNotExist(err) {
		err := os.Mkdir(fp, os.ModePerm)
		if err != nil {
			return "", fmt.Errorf("create dir for layer %s err %v", digest, err)
		}
	}

	fullFilePath := filepath.Join(fp, LayerFileName)
	logging.Get().Debug().Msgf("save file %s,digest %s,server root path %s,fp %s", fullFilePath, digest, fs.serverRootPath, fp)
	outFile, err := os.Create(fullFilePath)
	defer func() { outFile.Close() }()
	if err != nil {
		return "", fmt.Errorf("create layer file err,digest %s,err %v", digest, err)
	}

	_, err = io.Copy(outFile, r)
	if err != nil {
		return "", fmt.Errorf("copy layer file err,digest %s,err %v", digest, err)
	}

	_, err = os.Stat(fullFilePath)
	if err != nil {
		return "", fmt.Errorf("os state layer file err,digest %s,err %v", digest, err)
	}
	return fullFilePath, nil
}

func (fs *FileServer) DeleteFile(digest string) error {
	fullFilePath := filepath.Join(fs.serverRootPath, DataDir, digest)

	// only delete file,not directory
	err := os.RemoveAll(fullFilePath)
	logging.Get().Debug().Msgf("remove file %s,err %v", fullFilePath, err)
	if err != nil {
		return fmt.Errorf("remove layer file :%s err %v", fullFilePath, err)
	}
	return nil
}
