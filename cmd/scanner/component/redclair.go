package component

import (
	"context"
	"fmt"
	"os"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/util"
	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/flag"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/redclair"

	"github.com/heroku/docker-registry-client/registry"
)

// TODO: Temporary cache. Need something more robust
var cache = make(map[string]*model.CachedLayer)

const (
	scanOneTimeout = time.Minute * 5
	retryInterval  = time.Second * 5
)

// RedClair ...
type RedClairService struct {
	ctx     context.Context
	mongodb *mongo.Database

	scanTasksChan chan model.ScanTask

	redclairEngine *redclair.Redclair
}

// NewRedClair creates the instance of RedClair
func NewRedClairService(ctx context.Context, clairOpts *flag.ClairOpts, db *mongo.Database) (*RedClairService, error) {
	redclairEng, err := redclair.NewRedclair(clairOpts)
	if err != nil {
		return nil, err
	}
	return &RedClairService{
		ctx:            ctx,
		mongodb:        db,
		scanTasksChan:  make(chan model.ScanTask, 1000),
		redclairEngine: redclairEng,
	}, nil
}

// Run runs the RedClair instance
func (rcSvc *RedClairService) Run(ctx context.Context) {

	// Set scanner environment
	err := os.Setenv("DOCKER_API_VERSION", "1.38")
	if err != nil {
		log.Panic().Err(err).Msg("error in setting DOCKER_API_VERSION")
	}

	err = rcSvc.redclairEngine.StartImageHTTPServer()
	if err != nil {
		log.Panic().Err(err).Msg("Failed to start image http server")
	}
	defer rcSvc.redclairEngine.StopImageHTTPServer()

	// TODO do we want some max num of workers?
loop:
	for {
		select {
		case scanTask := <-rcSvc.scanTasksChan:
			go rcSvc.asyncProcessScanTask(ctx, scanTask)
		case <-ctx.Done():
			break loop
		}
	}
}

func (rcSvc *RedClairService) asyncProcessScanTask(ctx context.Context, scanTask model.ScanTask) {
	scanCtx, scanCtxCancel := context.WithTimeout(ctx, scanOneTimeout)
	defer scanCtxCancel()

	// TODO: Parse authorization from Harbor if needed
	hub, err := registry.New(scanTask.URL, "", "")
	if err != nil {
		log.Error().Err(err).Msg("Couldn't initialize docker registry client")
		scanTask.FinishedAt = time.Now().Unix()
		scanTask.Status = model.ScanStatusFailed
		scanTask.Message = err.Error()

		rcSvc.updateMongoStatus(ctx, scanTask)
		return
	}

	// TODO: Should we allow for v1?
	version := "v2"
	toResult := make([]string, 0)
	toScan := make([]string, 0)
	cacheTmp := make(map[string]*model.CachedLayer)
	rcSvc.readManifest(ctx, version, hub, scanTask, &toResult, &cacheTmp, &toScan)

	scanDoneCh := make(chan struct{})
	go func() {
		for i := range toScan {
			layersBench := make([]model.CachedLayer, 0)
			var currLayer model.CachedLayer
			if version == "v1" {
				currLayer = *cacheTmp[toScan[len(toScan)-i-1]]
			} else {
				currLayer = *cacheTmp[toScan[i]]
			}
			for {
				vulnInfo, fileSignatures, software, err := rcSvc.redclairEngine.ScanLayer(
					scanCtx,
					hub,
					currLayer.Digest,
					currLayer.Parent,
					scanTask.Image+"/"+scanTask.Tag,
				)
				if err != nil {
					switch err.(type) {
					default:
						log.Error().Err(err).Str("layerDigest", currLayer.Digest).Msg("Redclair scan failed. Retrying")
						time.Sleep(retryInterval)
					case ClairMissingParentLayerError:
						log.Info().Msg("Clair missing parent layer scan. Trying to scan parent next")
						layersBench = append(layersBench, currLayer)
						if _, exists := cache[currLayer.Parent]; exists {
							currLayer = *cache[currLayer.Parent]
						} else {
							currLayer = *cacheTmp[currLayer.Parent]
						}
					}
				} else {
					log.Info().Str("layerDigest", currLayer.Digest).Msg("Clair scan successful")
					if _, exists := cache[currLayer.Digest]; !exists {
						cache[currLayer.Digest] = cacheTmp[currLayer.Digest]
					}
					cache[currLayer.Digest].ScanReport = &model.ScanWorkerReport{
						Vulns:    vulnInfo,
						Files:    fileSignatures,
						Software: software,
					}
					if len(layersBench) > 0 {
						currLayer = layersBench[len(layersBench)-1]
						layersBench = layersBench[:len(layersBench)-1]
					} else {
						break
					}
				}
			}
		}
		scanDoneCh <- struct{}{}
	}()

	select {
	case <-scanDoneCh:
		log.Info().Msg("Redclair scan succeeded")

		scanTask.FinishedAt = time.Now().Unix()
		scanTask.Status = model.ScanStatusSucceeded
		report := &model.ScanReport{}
		vulns := make([]redclair.VulnerabilityInfo, 0)
		for _, digest := range toResult {
			vulns = append(vulns, cache[digest].ScanReport.Vulns...)
			report.Files = append(report.Files, cache[digest].ScanReport.Files...)
			report.Software = append(report.Software, cache[digest].ScanReport.Software...)
		}
		report.Vulns = redclair.VulnerabilityReport{
			scanTask.Repository,
			scanTask.Image,
			scanTask.ImageDigest,
			[]string{},
			vulns,
		}
		scanTask.ScanReport = *report
		rcSvc.updateMongoStatus(scanCtx, scanTask)

	case <-scanCtx.Done():
		log.Error().Err(ctx.Err()).Msg("Redclair scan timeout")

		scanTask.FinishedAt = time.Now().Unix()
		scanTask.Status = model.ScanStatusFailed
		scanTask.Message = ctx.Err().Error()

		rcSvc.updateMongoStatus(ctx, scanTask)
	}
}

// AddScanTask adds ScanTask to the internal channel
func (rcSvc *RedClairService) AddScanTask(task model.ScanTask) {
	rcSvc.scanTasksChan <- task
}

func (rcSvc *RedClairService) updateMongoStatus(ctx context.Context, scanTask model.ScanTask) {
	mongoCtx, mongoCtxCancel := context.WithTimeout(ctx, time.Second*10)
	defer mongoCtxCancel()

	filter := bson.M{"_id": scanTask.ID}
	update := bson.M{"$set": scanTask}

	_, err := rcSvc.mongodb.Collection(model.ScanTasksCollection).UpdateOne(mongoCtx, filter, update)
	if err != nil {
		log.Error().
			Err(err).
			Str("scanTask", fmt.Sprintf("%+v", scanTask)).
			Msg("error in updating task in Mongo")
	}
}

func (rcSvc *RedClairService) readManifest(ctx context.Context, version string, hub *registry.Registry, scanTask model.ScanTask, toResult *[]string, cacheTmp *map[string]*model.CachedLayer, toScan *[]string) {
	if version == "v1" {
		manifest, err := hub.Manifest(scanTask.Image, scanTask.Tag)
		if err != nil {
			log.Error().Err(err).Msg("Could not read docker V1 manifest")

			scanTask.FinishedAt = time.Now().Unix()
			scanTask.Status = model.ScanStatusFailed
			scanTask.Message = err.Error()

			rcSvc.updateMongoStatus(ctx, scanTask)
			return
		}
		manifestDigest, err := hub.ManifestDigest(scanTask.Image, scanTask.Tag)
		if err != nil {
			log.Error().Err(err).Msg("Could not get docker V1 manifest digest")

			scanTask.FinishedAt = time.Now().Unix()
			scanTask.Status = model.ScanStatusFailed
			scanTask.Message = err.Error()

			rcSvc.updateMongoStatus(ctx, scanTask)
			return
		}
		first := true
		var prevDigest string
		for _, layer := range manifest.Manifest.FSLayers {
			layerDigest := layer.BlobSum
			*toResult = append(*toResult, layerDigest.String())
			var currCache = cache
			if _, exists := cache[layerDigest.String()]; !exists {
				log.Info().Str("layerDigest", layerDigest.String()).Msg("Layer not cached. Need to scan")
				(*cacheTmp)[layerDigest.String()] = &model.CachedLayer{
					Digest: layerDigest.String(),
				}
				currCache = *cacheTmp
				*toScan = append(*toScan, layerDigest.String())
			} else {
				log.Info().Str("layerDigest", layerDigest.String()).Msg("Layer cached. No need to scan")
			}
			if first {
				currCache[layerDigest.String()].ImageDigests = util.AppendIfMissing(currCache[layerDigest.String()].ImageDigests, manifestDigest.String())
				currCache[layerDigest.String()].Images = util.AppendIfMissing(currCache[layerDigest.String()].Images, scanTask.Image)
				currCache[layerDigest.String()].Tags = util.AppendIfMissing(currCache[layerDigest.String()].Tags, scanTask.Tag)
				first = false
			} else {
				currCache[prevDigest].Parent = layerDigest.String()
			}
			prevDigest = layerDigest.String()
		}
	} else if version == "v2" {
		manifest, err := hub.ManifestV2(scanTask.Image, scanTask.Tag)
		if err != nil {
			log.Error().Err(err).Msg("Could not read docker V2 manifest")

			scanTask.FinishedAt = time.Now().Unix()
			scanTask.Status = model.ScanStatusFailed
			scanTask.Message = err.Error()

			rcSvc.updateMongoStatus(ctx, scanTask)
			return
		}
		manifestDigest, err := hub.ManifestDigest(scanTask.Image, scanTask.Tag)
		if err != nil {
			log.Error().Err(err).Msg("Could not get docker V2 manifest digest")

			scanTask.FinishedAt = time.Now().Unix()
			scanTask.Status = model.ScanStatusFailed
			scanTask.Message = err.Error()

			rcSvc.updateMongoStatus(ctx, scanTask)
			return
		}
		var prevDigest string
		first := true
		var currCache = cache
		for _, layer := range manifest.Manifest.Layers {
			currCache = cache
			layerDigest := layer.Digest
			*toResult = append(*toResult, layerDigest.String())
			if _, exists := cache[layerDigest.String()]; !exists {
				log.Info().Str("layerDigest", layerDigest.String()).Msg("Layer not cached. Need to scan")
				(*cacheTmp)[layerDigest.String()] = &model.CachedLayer{
					Digest: layerDigest.String(),
				}
				currCache = *cacheTmp
				*toScan = append(*toScan, layerDigest.String())
			} else {
				log.Info().Str("layerDigest", layerDigest.String()).Msg("Layer cached. No need to scan")
			}
			if first {
				first = false
			} else {
				currCache[layerDigest.String()].Parent = prevDigest
			}
			prevDigest = layerDigest.String()
		}
		currCache[prevDigest].ImageDigests = util.AppendIfMissing(currCache[prevDigest].ImageDigests, manifestDigest.String())
		currCache[prevDigest].Images = util.AppendIfMissing(currCache[prevDigest].Images, scanTask.Image)
		currCache[prevDigest].Tags = util.AppendIfMissing(currCache[prevDigest].Tags, scanTask.Tag)
	}
}
