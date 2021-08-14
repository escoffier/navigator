package layerManage

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"gitlab.com/piccolo_su/vegeta/pkg/logging"
)

const (
	FileServerRootDir = "layerManage"
	LayerFileName     = "layer.tar"
	FileServerCache   = "FileServerCache"
)

var (
	log *logging.Logger
)

type FileServer struct {
	ctx            context.Context
	rootPath       string
	port           int
	serverIp       string
	externalIp     string
	server         *http.Server
	serverRootPath string //actual server root path: /tmp/xxx
}

func init() {
	log = logging.GetLogger()
}

func NewFileServer(ctx context.Context, rootPath, externalIp, serverIp string, port int) (*FileServer, error) {
	fs := &FileServer{
		ctx:        ctx,
		rootPath:   rootPath,
		port:       port,
		serverIp:   serverIp,
		externalIp: externalIp,
	}

	return fs, nil
}

func (fs *FileServer) CreateHTTPRootDir() error {
	err := os.Mkdir(FileServerCache, 0777)
	if err != nil {
		return err
	}
	fs.serverRootPath = filepath.Join(FileServerCache, FileServerRootDir)
	return os.MkdirAll(fs.serverRootPath, os.ModePerm)
}

func (fs *FileServer) CreateFileServer() error {
	mux := http.NewServeMux()
	mux.Handle("/", http.FileServer(http.Dir(fs.serverRootPath)))
	fs.server = &http.Server{
		// listen on all IPs
		Addr:    fmt.Sprintf("%s:%d", fs.serverIp, fs.port),
		Handler: mux,
	}
	return nil
}

func (fs *FileServer) StartFileServer() error {
	go func() {
		if err := fs.server.ListenAndServe(); err != nil {
			if err != nil {
				log.Error().Msgf("file server start err %v", err)
			}
		}
	}()
	// It takes some time to open the port, just to be sure we wait a bit
	time.Sleep(100 * time.Millisecond)
	log.Info().Msgf("Server layer manage file server on port %d", fs.port)
	return nil
}

func (fs *FileServer) StopFileServer() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := fs.server.Shutdown(ctx); err != nil {
		log.Error().
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
	fp := filepath.Join(fs.serverRootPath, digest)
	if _, err := os.Stat(fp); os.IsNotExist(err) {
		err := os.Mkdir(fp, os.ModePerm)
		if err != nil {
			return "", fmt.Errorf("create dir for layer %s err %v", digest, err)
		}
	}

	fullFilePath := filepath.Join(fp, LayerFileName)
	log.Info().Msgf("save file %s,digest %s,server root path %s,fp %s", fullFilePath, digest, fs.serverRootPath, fp)
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
	fullFilePath := filepath.Join(fs.serverRootPath, digest, LayerFileName)

	//only delete file,not directory
	err := os.RemoveAll(fullFilePath)
	log.Info().Msgf("remove file %s,err %v", fullFilePath, err)
	if err != nil {
		return fmt.Errorf("remove layer file :%s err %v", fullFilePath, err)
	}
	return nil
}
