package component

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/util"
	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/flag"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/redclair"

	"database/sql"

	"github.com/go-redis/redis/v8"
	"github.com/heroku/docker-registry-client/registry"
	"github.com/rs/zerolog"

	_ "github.com/lib/pq"
)

const (
	scanOneTimeout           = time.Minute * 5
	retryInterval            = time.Second * 5
	mongoTimeout             = time.Second * 10
	redisTimeout             = time.Second * 10
	redisCleanupTimeout      = time.Minute * 1
	cacheInvalidatorInterval = time.Hour * 3
	maxLayerScanRetires      = 10
)

// RedClair ...
type RedClairService struct {
	ctx         context.Context
	mongodb     *mongo.Database
	redisClient *redis.Client

	scanTasksChan chan model.ScanTask
	numWorkers    int

	redclairEngine *redclair.Redclair

	skipRegistryTLSVerify bool

	clairDBConnectionString string
}

// NewRedClair creates the instance of RedClair
func NewRedClairService(ctx context.Context, clairOpts *flag.ClairOpts, db *mongo.Database, rc *redis.Client) (*RedClairService, error) {
	redclairEng, err := redclair.NewRedclair(clairOpts)
	if err != nil {
		return nil, err
	}
	return &RedClairService{
		ctx:                     ctx,
		mongodb:                 db,
		redisClient:             rc,
		scanTasksChan:           make(chan model.ScanTask, 1000),
		numWorkers:              clairOpts.NumWorkers,
		redclairEngine:          redclairEng,
		skipRegistryTLSVerify:   clairOpts.SkipRegistryTLSVerify,
		clairDBConnectionString: clairOpts.PostgresConnectionString,
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

	var wg sync.WaitGroup
	wg.Add(1)
	go rcSvc.CacheInvalidatorRun(ctx, &wg)
	log.Info().Msg("Started cache invalidator")

	for i := 0; i < rcSvc.numWorkers; i++ {
		wg.Add(1)
		go rcSvc.WorkerRun(ctx, i, &wg)
	}
	log.Info().Msg("Started all Redclair workers")
	wg.Wait()
	log.Info().Msg("All Redclair workers finished")
}

func (rcSvc *RedClairService) CacheInvalidatorRun(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	cacheInvalidatorSublogger := log.With().Int("cacheinvalidator-id", 0).Logger()
	ctx = cacheInvalidatorSublogger.WithContext(ctx)
	zerolog.Ctx(ctx).Info().Msg("Started Redclair cache invalidator service")
	rcSvc.updateLayerCache(ctx)
	ticker := time.NewTicker(cacheInvalidatorInterval)
loop:
	for {
		select {
		case <-ticker.C:
			rcSvc.updateLayerCache(ctx)
		case <-ctx.Done():
			break loop
		}
	}
	zerolog.Ctx(ctx).Info().Msg("Shutting down Redclair worker")
}

func (rcSvc *RedClairService) WorkerRun(ctx context.Context, id int, wg *sync.WaitGroup) {
	defer wg.Done()

	workerSublogger := log.With().Int("worker-id", id).Logger()
	ctx = workerSublogger.WithContext(ctx)

	zerolog.Ctx(ctx).Info().Msg("Started Redclair worker")
loop:
	for {
		select {
		case scanTask := <-rcSvc.scanTasksChan:
			rcSvc.asyncProcessScanTask(ctx, scanTask)
		case <-ctx.Done():
			break loop
		}
	}
	zerolog.Ctx(ctx).Info().Msg("Shutting down Redclair worker")
}

func (rcSvc *RedClairService) getUpdatedAt(ctx context.Context) int64 {
	lastUpdateTime := int64(0)
	lastUpdateTimeStr, err := rcSvc.redisClient.Get(ctx, "DBupdate").Result()
	if err == redis.Nil {
		zerolog.Ctx(ctx).Info().Msg("Haven't cached DB last update yet")
	} else if err != nil {
		zerolog.Ctx(ctx).Err(err).Msg("Error getting DB update time from cache")
	} else {
		lastUpdateTime, err = strconv.ParseInt(lastUpdateTimeStr, 10, 64)
		if err != nil {
			zerolog.Ctx(ctx).Err(err).Msg("Error converting DBupdateTime from cache to int64")
		}
	}
	return lastUpdateTime
}

func (rcSvc *RedClairService) getVulnerabilityUpdatedAt(ctx context.Context) string {
	lastUpdateVulnerability, err := rcSvc.redisClient.Get(ctx, "lastUpdateVulnerability").Result()
	if err == redis.Nil {
		zerolog.Ctx(ctx).Info().Msg("Haven't cached DB vulnerability last update yet")
	} else if err != nil {
		zerolog.Ctx(ctx).Err(err).Msg("Error getting DB vulnerability update time from cache")
	} else {
		return lastUpdateVulnerability
	}
	return ""
}

func (rcSvc *RedClairService) updateLayerCache(ctx context.Context) {
	zerolog.Ctx(ctx).Info().Msg("Started cache invalidator worker")
	db, err := sql.Open("postgres", rcSvc.clairDBConnectionString)
	if err != nil {
		zerolog.Ctx(ctx).Err(err).Msg("Failed to open Clair DB connection")
	}
	defer db.Close()

	var lastUpdate model.DBUpdateTime
	lastUpdateQuery := "SELECT value FROM keyvalue WHERE key='updater/last'"
	err = db.QueryRow(lastUpdateQuery).Scan(&lastUpdate.Value)
	if err != nil {
		zerolog.Ctx(ctx).Err(err).Msg("Failed to execute query")
		return
	}

	lastUpdatedTime := rcSvc.getUpdatedAt(ctx)
	if lastUpdatedTime < lastUpdate.Value {
		_, err := rcSvc.redisClient.Set(ctx, "DBupdate", strconv.FormatInt(lastUpdate.Value, 10), redis.KeepTTL).Result()
		if err != nil {
			zerolog.Ctx(ctx).Error().Err(err).Msg("Cannot persist DB update time to cache.")
		}
		zerolog.Ctx(ctx).Info().Msg("DB update time successfully persisted in cache")
	}

	namespacesToRemove := make([]string, 0)

	lastUpdateVulnerability := rcSvc.getVulnerabilityUpdatedAt(ctx)

	if lastUpdateVulnerability != "" {
		newVulnerabilitiesQuery := fmt.Sprintf("select a.name, c.name as namespace from (select distinct name, namespace_id from vulnerability where created_at > timestamp '%s') as a left join (select distinct name, namespace_id from vulnerability where created_at <= timestamp '%s') as b on a.name = b.name and a.namespace_id = b.namespace_id left join namespace c on a.namespace_id = c.id where b.name is null;", lastUpdateVulnerability, lastUpdateVulnerability)
		vulnerabilityEntry := model.DBVulnerabilityEntry{}
		rows, err := db.Query(newVulnerabilitiesQuery)
		defer rows.Close()
		for rows.Next() {
			err := rows.Scan(&vulnerabilityEntry.Name, &vulnerabilityEntry.NameSpace)
			if err != nil {
				zerolog.Ctx(ctx).Err(err).Msg("Failed to get new vulnerability entry")
			} else {
				namespacesToRemove = util.AppendIfMissing(namespacesToRemove, vulnerabilityEntry.NameSpace)
			}
		}
		err = rows.Err()
		if err != nil {
			zerolog.Ctx(ctx).Err(err).Msg("Failed to get new vulnerability entries")
		}
	}

	// TODO: Below is not tested
	if lastUpdateVulnerability != "" {
		removedVulnerabilitiesQuery := fmt.Sprintf("select a.name, c.name as namespace from (select name, namespace_id, max(CASE WHEN deleted_at IS NULL THEN timestamp '9999-01-01 00:00:00.000000+00' ELSE deleted_at END) as deleted_at from vulnerability where created_at > timestamp '%s' group by namespace_id, name) as a left join (select name, namespace_id, max(CASE WHEN deleted_at IS NULL THEN timestamp '9999-01-01 00:00:00.000000+00' ELSE deleted_at END) as deleted_at from vulnerability where created_at <= timestamp '%s' group by namespace_id, name) as b on a.name=b.name and a.namespace_id=b.namespace_id left join namespace c on a.namespace_id=c.id where b.deleted_at = timestamp '9999-01-01 00:00:00.000000+00' and a.deleted_at != timestamp '9999-01-01 00:00:00.000000+00';", lastUpdateVulnerability, lastUpdateVulnerability)

		vulnerabilityEntry := model.DBVulnerabilityEntry{}
		rows, err := db.Query(removedVulnerabilitiesQuery)
		defer rows.Close()
		for rows.Next() {
			err := rows.Scan(&vulnerabilityEntry.Name, &vulnerabilityEntry.NameSpace)
			if err != nil {
				zerolog.Ctx(ctx).Err(err).Msg("Failed to get removed vulnerability entry")
			} else {
				namespacesToRemove = util.AppendIfMissing(namespacesToRemove, vulnerabilityEntry.NameSpace)
			}
		}
		err = rows.Err()
		if err != nil {
			zerolog.Ctx(ctx).Err(err).Msg("Failed to get removed vulnerability entries")
		}
	}

	if lastUpdateVulnerability == "" || len(namespacesToRemove) > 0 {
		var dbVulnerabilityUpdateTime model.DBVulnerabilityUpdateTime
		lastUpdateVulnerabilityQuery := "SELECT max(created_at) from vulnerability"
		err = db.QueryRow(lastUpdateVulnerabilityQuery).Scan(&dbVulnerabilityUpdateTime.MaxCreatedAt)
		if err != nil {
			zerolog.Ctx(ctx).Err(err).Msg("Failed to get vulnerability update time")
		}
		_, err := rcSvc.redisClient.Set(ctx, "lastUpdateVulnerability", dbVulnerabilityUpdateTime.MaxCreatedAt, redis.KeepTTL).Result()
		if err != nil {
			zerolog.Ctx(ctx).Error().Err(err).Msg("Cannot persist DB vulnerability update time to cache.")
		}
		zerolog.Ctx(ctx).Info().Msg("DB vulnerability update time successfully persisted in cache")
	}

	redisCtx, redisCtxCancel := context.WithTimeout(ctx, redisCleanupTimeout)
	defer redisCtxCancel()
	for _, namespacesToRemove := range namespacesToRemove {
		iter := rcSvc.redisClient.Scan(redisCtx, 0, namespacesToRemove+"*", 0).Iterator()
		for iter.Next(redisCtx) {
			layerToRemove := iter.Val()
			err := rcSvc.redisClient.Del(redisCtx, layerToRemove).Err()
			if err != nil {
				zerolog.Ctx(ctx).Err(err).Str("digest", layerToRemove).Msg("Failed to remove layer from cache")
			} else {
				zerolog.Ctx(ctx).Info().Str("digest", layerToRemove).Msg("Successfully removed from cache")
			}
		}
		if err := iter.Err(); err != nil {
			zerolog.Ctx(ctx).Err(err).Msg("Failed to iterate over cache entries")
		}
	}
}

func (rcSvc *RedClairService) asyncProcessScanTask(ctx context.Context, scanTask model.ScanTask) {
	scanCtx, scanCtxCancel := context.WithTimeout(ctx, scanOneTimeout)
	defer scanCtxCancel()

	username := ""
	password := ""
	if scanTask.Authorization != "" {
		var err error
		username, password, err = rcSvc.decodeUsernamePassword(scanTask)
		if err != nil {
			zerolog.Ctx(ctx).Error().Err(err).Msg("Couldn't decode username and password")
			scanTask.FinishedAt = time.Now().Unix()
			scanTask.Status = model.ScanStatusFailed
			scanTask.Message = fmt.Sprintf("Couldn't decode username and password: %s", err)

			rcSvc.updateMongoStatus(ctx, scanTask)
			return
		}
	}

	hub, err := registry.New(scanTask.URL, username, password)
	if err != nil && rcSvc.skipRegistryTLSVerify {
		// seems like error Golang's x509 package doesn't support error wrapping API yet:
		// https://github.com/golang/go/issues/30322
		//var hostnameErr *x509.HostnameError
		//if errors.As(err, &hostnameErr) { ... }
		// Therefore we must unwrap the error from HTTP package manually and try to cast

		// Check for any type of error defined in x509 package.
		_, ok1 := errors.Unwrap(err).(x509.SystemRootsError)
		_, ok2 := errors.Unwrap(err).(x509.CertificateInvalidError)
		_, ok3 := errors.Unwrap(err).(x509.UnknownAuthorityError)
		_, ok4 := errors.Unwrap(err).(x509.HostnameError)
		if ok1 || ok2 || ok3 || ok4 {
			zerolog.Ctx(ctx).Warn().Err(err).Msg("Certificate validation failed, but insecure option is on - will retry and skip TLS cert verification")
			hub, err = registry.NewInsecure(scanTask.URL, username, password)
		}
	}
	if err != nil {
		zerolog.Ctx(ctx).Error().Err(err).Msg("Couldn't initialize docker registry client")
		scanTask.FinishedAt = time.Now().Unix()
		scanTask.Status = model.ScanStatusFailed
		scanTask.Message = fmt.Sprintf("Couldn't initialize docker registry client: %s", err)

		rcSvc.updateMongoStatus(ctx, scanTask)
		return
	}

	// TODO: Should we allow for v1?
	version := "v2"
	toResult := make([]string, 0)
	toScan := make([]string, 0)
	cacheTmp := make(map[string]*model.CachedLayer)
	namespace, err := rcSvc.readManifest(ctx, version, hub, scanTask, &toResult, &cacheTmp, &toScan)
	if err != nil {
		zerolog.Ctx(ctx).Error().Err(err).Msg("Couldn't read manifest")
		scanTask.FinishedAt = time.Now().Unix()
		scanTask.Status = model.ScanStatusFailed
		scanTask.Message = fmt.Sprintf("Couldn't read manifest: %s", err)

		rcSvc.updateMongoStatus(ctx, scanTask)
		return
	}
	if namespace == "" {
		namespace = "anonymous"
	}

	scanDoneCh := make(chan struct{})
	scanErrorCh := make(chan struct{})
	go func() {
		for i := range toScan {
			layersBench := make([]model.CachedLayer, 0)
			var currLayer model.CachedLayer
			if version == "v1" {
				currLayer = *cacheTmp[toScan[len(toScan)-i-1]]
			} else {
				currLayer = *cacheTmp[toScan[i]]
			}
			retryCounter := 0
			for retryCounter <= maxLayerScanRetires {
				layerNamespace, vulnInfo, fileSignatures, software, err := rcSvc.redclairEngine.ScanLayer(
					scanCtx,
					hub,
					currLayer.Digest,
					currLayer.Parent,
					scanTask.Repository,
				)
				if err != nil {
					switch err.(type) {
					default:
						zerolog.Ctx(ctx).Error().Err(err).Int("retryCounter", retryCounter).Str("layerDigest", currLayer.Digest).Msg("Redclair scan failed. Retrying")
						time.Sleep(retryInterval)
						retryCounter++
					case ClairMissingParentLayerError:
						zerolog.Ctx(ctx).Info().Msg("Clair missing parent layer scan. Trying to scan parent next")
						layersBench = append(layersBench, currLayer)
						parentLayerDigest := currLayer.Parent
						cachedLayer := &model.CachedLayer{
							Digest: parentLayerDigest,
						}
						iter := rcSvc.redisClient.Scan(ctx, 0, "*"+parentLayerDigest, 0).Iterator()
						if iter.Next(ctx) {
							v := iter.Val()
							namespace = strings.Split(v, "_")[0]
							cacheEntry, err := rcSvc.redisClient.Get(ctx, v).Result()
							if err == redis.Nil {
								zerolog.Ctx(ctx).Info().Str("layerDigest", parentLayerDigest).Msg("Weird...")
								currLayer = *cacheTmp[currLayer.Parent]
							} else if err != nil {
								zerolog.Ctx(ctx).Err(err).Str("layerDigest", parentLayerDigest).Msg("Error getting layer from cache")
								currLayer = *cacheTmp[currLayer.Parent]
							} else {
								err = json.Unmarshal([]byte(cacheEntry), cachedLayer)
								if err != nil {
									zerolog.Ctx(ctx).Err(err).Str("layerDigest", parentLayerDigest).Msg("Layer could not be unmarshaled.")
									currLayer = *cacheTmp[currLayer.Parent]
								} else {
									currLayer = *cachedLayer
								}
							}
						} else {
							zerolog.Ctx(ctx).Info().Str("layerDigest", parentLayerDigest).Msg("Parent layer not cached")
							currLayer = *cacheTmp[currLayer.Parent]
						}
						if err := iter.Err(); err != nil {
							zerolog.Ctx(ctx).Err(err).Str("layerDigest", parentLayerDigest).Msg("Failed to iterate over cache entries")
							currLayer = *cacheTmp[currLayer.Parent]
						}
					}
				} else {
					zerolog.Ctx(ctx).Info().Str("layerDigest", currLayer.Digest).Msg("Clair scan successful")
					cacheTmp[currLayer.Digest].ScanReport = &model.ScanWorkerReport{
						Vulns:    vulnInfo,
						Files:    fileSignatures,
						Software: software,
					}
					cacheTmp[currLayer.Digest].NameSpace = namespace
					_, err := rcSvc.redisClient.Get(ctx, layerNamespace+"_"+currLayer.Digest).Result()
					if err == redis.Nil {
						zerolog.Ctx(ctx).Info().Str("layerDigest", currLayer.Digest).Msg("Persisting in cache")
						cacheEntry, err := json.Marshal(cacheTmp[currLayer.Digest])
						if err != nil {
							zerolog.Ctx(ctx).Err(err).Str("layerDigest", currLayer.Digest).Msg("Layer could not be marshaled.")
						} else {
							redisCtx, redisCtxCancel := context.WithTimeout(ctx, redisTimeout)
							defer redisCtxCancel()
							_, err := rcSvc.redisClient.Set(redisCtx, layerNamespace+"_"+currLayer.Digest, cacheEntry, redis.KeepTTL).Result()
							if err != nil {
								zerolog.Ctx(ctx).Error().Err(err).Str("layerDigest", currLayer.Digest).Msg("Layer could not be cached.")
							}
							zerolog.Ctx(ctx).Info().Str("layerDigest", currLayer.Digest).Msg("Layer successfully cached")
						}
					} else if err != nil {
						zerolog.Ctx(ctx).Err(err).Str("layerDigest", currLayer.Digest).Msg("Error getting layer from cache. Not persisting")
					} else {
						zerolog.Ctx(ctx).Info().Str("layerDigest", currLayer.Digest).Msg("Another worker recently scanned this layer. No need to persist")
					}
					if len(layersBench) > 0 {
						currLayer = layersBench[len(layersBench)-1]
						layersBench = layersBench[:len(layersBench)-1]
					} else {
						break
					}
				}
			}
			if retryCounter > maxLayerScanRetires {
				scanErrorCh <- struct{}{}
			}

		}
		scanDoneCh <- struct{}{}
	}()

	select {
	case <-scanErrorCh:
		zerolog.Ctx(ctx).Error().Msg("Redclair scan failed")
		scanTask.FinishedAt = time.Now().Unix()
		scanTask.Status = model.ScanStatusFailed
		scanTask.Message = fmt.Sprintf("Couldn't read manifest: %s", err)

		rcSvc.updateMongoStatus(ctx, scanTask)
		return

	case <-scanDoneCh:
		zerolog.Ctx(ctx).Info().Msg("Redclair scan succeeded")

		scanTask.FinishedAt = time.Now().Unix()
		scanTask.Status = model.ScanStatusSucceeded
		report := &model.ScanReport{}
		vulns := make([]redclair.VulnerabilityInfo, 0)
		for _, digest := range toResult {
			cachedLayer := &model.CachedLayer{
				Digest: digest,
			}
			iter := rcSvc.redisClient.Scan(ctx, 0, "*"+digest, 0).Iterator()
			if iter.Next(ctx) {
				v := iter.Val()
				cacheEntry, err := rcSvc.redisClient.Get(ctx, v).Result()
				if err == redis.Nil {
					// Such situation could happen, if in the meantime the cache cleaning process has removed
					// this entry (because the clair database has updated for tree containing this layer).
					// In such case return the local cache result.
					zerolog.Ctx(ctx).Info().Str("layerDigest", digest).Msg("Cached entry cleared during scanning the image. Taking the local cache entry")
					cachedLayer = cacheTmp[digest]
				} else if err != nil {
					zerolog.Ctx(ctx).Err(err).Str("layerDigest", digest).Msg("Error getting layer from cache")
					cachedLayer = cacheTmp[digest]
				} else {
					err = json.Unmarshal([]byte(cacheEntry), cachedLayer)
					if err != nil {
						zerolog.Ctx(ctx).Err(err).Str("layerDigest", digest).Msg("Layer could not be unmarshaled.")
						cachedLayer = cacheTmp[digest]
					}
				}
				vulns = append(vulns, cachedLayer.ScanReport.Vulns...)
				report.Files = append(report.Files, cachedLayer.ScanReport.Files...)
				report.Software = append(report.Software, cachedLayer.ScanReport.Software...)

			} else {
				// Such situation could happen, if in the meantime the cache cleaning process has removed
				// this entry (because the clair database has updated for tree containing this layer).
				// In such case return the local cache result.
				zerolog.Ctx(ctx).Info().Str("layerDigest", digest).Msg("Cached entry cleared during scanning the image. Taking the local cache entry")
				cachedLayer = cacheTmp[digest]
			}
			if err := iter.Err(); err != nil {
				zerolog.Ctx(ctx).Err(err).Str("layerDigest", digest).Msg("Failed to iterate over cache entries")
				cachedLayer = cacheTmp[digest]
			}
		}
		report.Vulns = redclair.VulnerabilityReport{
			Repository:      scanTask.Repository,
			Tag:             scanTask.Tag,
			Digest:          scanTask.ImageDigest,
			Unapproved:      []string{},
			Vulnerabilities: vulns,
		}
		scanTask.ScanReport = *report
		rcSvc.updateMongoStatus(scanCtx, scanTask)

	case <-scanCtx.Done():
		zerolog.Ctx(ctx).Error().Err(ctx.Err()).Msg("Redclair scan timeout")

		scanTask.FinishedAt = time.Now().Unix()
		scanTask.Status = model.ScanStatusFailed
		scanTask.Message = ctx.Err().Error()

		rcSvc.updateMongoStatus(ctx, scanTask)
	}
}

func (rcSvc *RedClairService) decodeUsernamePassword(scanTask model.ScanTask) (string, string, error) {
	// scanTask.Authorization == Basic cm9ib3QkdHMt...

	headerSplit := strings.Split(scanTask.Authorization, " ")
	if len(headerSplit) != 2 {
		return "", "", fmt.Errorf("Expected 'Basic ASDF' format, but got different")
	}
	b64Encoded := headerSplit[1]

	decodedHeader, err := base64.StdEncoding.DecodeString(b64Encoded)
	if err != nil {
		return "", "", fmt.Errorf("Couldn't decode auth string: %w", err)
	}

	// decodedHeader == robot$ts-cdffae66-0edd-11eb-91a9-4e1d0aed31d4:eyJhbGciOiJSUzI1...

	usernamePasswordArr := strings.Split(string(decodedHeader), ":")
	if len(usernamePasswordArr) != 2 {
		return "", "", fmt.Errorf("Expected 'username:password' format, but got different")
	}

	username := usernamePasswordArr[0]
	password := usernamePasswordArr[1]

	return username, password, nil
}

// AddScanTask adds ScanTask to the internal channel
func (rcSvc *RedClairService) AddScanTask(task model.ScanTask) {
	rcSvc.scanTasksChan <- task
}

func (rcSvc *RedClairService) updateMongoStatus(ctx context.Context, scanTask model.ScanTask) {
	mongoCtx, mongoCtxCancel := context.WithTimeout(ctx, mongoTimeout)
	defer mongoCtxCancel()

	filter := bson.M{"_id": scanTask.ID}
	update := bson.M{"$set": scanTask}

	_, err := rcSvc.mongodb.Collection(model.ScanTasksCollection).UpdateOne(mongoCtx, filter, update)
	if err != nil {
		zerolog.Ctx(ctx).Error().
			Err(err).
			Str("scanTask", fmt.Sprintf("%+v", scanTask)).
			Msg("error in updating task in Mongo")
	}
}

func (rcSvc *RedClairService) readManifest(ctx context.Context, version string, hub *registry.Registry, scanTask model.ScanTask, toResult *[]string, cacheTmp *map[string]*model.CachedLayer, toScan *[]string) (string, error) {
	// TODO: fix getting namespae of V1 manifests
	namespace := ""
	if version == "v1" {
		manifest, err := hub.Manifest(scanTask.Repository, scanTask.ImageDigest)
		if err != nil {
			return "", fmt.Errorf("Could not read docker V1 manifest: %w", err)
		}
		manifestDigest, err := hub.ManifestDigest(scanTask.Repository, scanTask.ImageDigest)
		if err != nil {
			return "", fmt.Errorf("Could not get docker V1 manifest digest: %w", err)
		}
		first := true
		var prevLayer *model.CachedLayer
		for _, layer := range manifest.Manifest.FSLayers {
			layerDigest := layer.BlobSum.String()
			*toResult = append(*toResult, layerDigest)
			cachedLayer := &model.CachedLayer{
				Digest: layerDigest,
			}
			cacheEntry, err := rcSvc.redisClient.Get(ctx, layerDigest).Result()
			if err == redis.Nil {
				zerolog.Ctx(ctx).Info().Str("layerDigest", layerDigest).Msg("Layer not cached. Need to scan")
				cachedLayer.Digest = layerDigest
				(*cacheTmp)[layerDigest] = cachedLayer
				*toScan = append(*toScan, layerDigest)
			} else if err != nil {
				zerolog.Ctx(ctx).Err(err).Str("layerDigest", layerDigest).Msg("Error getting layer from cache")
				cachedLayer.Digest = layerDigest
				(*cacheTmp)[layerDigest] = cachedLayer
				*toScan = append(*toScan, layerDigest)
			} else {
				err = json.Unmarshal([]byte(cacheEntry), cachedLayer)
				if err != nil {
					zerolog.Ctx(ctx).Err(err).Str("layerDigest", layerDigest).Msg("Layer could not be unmarshaled.")
					*toScan = append(*toScan, layerDigest)
				} else {
					zerolog.Ctx(ctx).Info().Str("layerDigest", layerDigest).Msg("Layer cached. No need to scan")
				}
				(*cacheTmp)[layerDigest] = cachedLayer
			}
			if first {
				cachedLayer.ImageDigests = util.AppendIfMissing(cachedLayer.ImageDigests, manifestDigest.String())
				cachedLayer.Repositories = util.AppendIfMissing(cachedLayer.Repositories, scanTask.Repository)
				cachedLayer.Tags = util.AppendIfMissing(cachedLayer.Tags, scanTask.Tag)
				first = false
			} else {
				(*cacheTmp)[prevLayer.Digest].Parent = layerDigest
			}
			prevLayer = cachedLayer
		}
		for key := range *cacheTmp {
			(*cacheTmp)[key] = (*cacheTmp)[key]
			delete((*cacheTmp), key)
		}
	} else if version == "v2" {
		manifest, err := hub.ManifestV2(scanTask.Repository, scanTask.ImageDigest)
		if err != nil {
			return "", fmt.Errorf("Could not read docker V2 manifest: %w", err)
		}
		manifestDigest, err := hub.ManifestDigest(scanTask.Repository, scanTask.ImageDigest)
		if err != nil {
			return "", fmt.Errorf("Could not get docker V2 manifest digest: %w", err)
		}
		var prevLayer *model.CachedLayer
		var cachedLayer *model.CachedLayer
		first := true
		for _, layer := range manifest.Manifest.Layers {
			layerDigest := layer.Digest.String()
			*toResult = append(*toResult, layerDigest)
			cachedLayer = &model.CachedLayer{
				Digest: layerDigest,
			}
			iter := rcSvc.redisClient.Scan(ctx, 0, "*"+layerDigest, 0).Iterator()
			if iter.Next(ctx) {
				v := iter.Val()
				namespace = strings.Split(v, "_")[0]
				cacheEntry, err := rcSvc.redisClient.Get(ctx, v).Result()
				if err == redis.Nil {
					zerolog.Ctx(ctx).Info().Str("layerDigest", layerDigest).Msg("Really weird...")
					(*cacheTmp)[layerDigest] = cachedLayer
					*toScan = append(*toScan, layerDigest)
				} else if err != nil {
					zerolog.Ctx(ctx).Err(err).Str("layerDigest", layerDigest).Msg("Error getting layer from cache")
					(*cacheTmp)[layerDigest] = cachedLayer
					*toScan = append(*toScan, layerDigest)
				} else {
					err = json.Unmarshal([]byte(cacheEntry), cachedLayer)
					if err != nil {
						zerolog.Ctx(ctx).Err(err).Str("layerDigest", layerDigest).Msg("Layer could not be unmarshaled.")
						*toScan = append(*toScan, layerDigest)
					} else {
						zerolog.Ctx(ctx).Info().Str("layerDigest", layerDigest).Msg("Layer cached. No need to scan")
					}
					(*cacheTmp)[layerDigest] = cachedLayer
				}
			} else {
				zerolog.Ctx(ctx).Info().Str("layerDigest", layerDigest).Msg("Layer not cached. Need to scan")
				(*cacheTmp)[layerDigest] = cachedLayer
				*toScan = append(*toScan, layerDigest)
			}
			if err := iter.Err(); err != nil {
				zerolog.Ctx(ctx).Err(err).Msg("Failed to iterate over cache entries")
				(*cacheTmp)[layerDigest] = cachedLayer
				*toScan = append(*toScan, layerDigest)
			}
			if first {
				first = false
			} else {
				(*cacheTmp)[layerDigest].Parent = prevLayer.Digest
			}
			prevLayer = cachedLayer
		}
		cachedLayer.ImageDigests = util.AppendIfMissing(cachedLayer.ImageDigests, manifestDigest.String())
		cachedLayer.Repositories = util.AppendIfMissing(cachedLayer.Repositories, scanTask.Repository)
		cachedLayer.Tags = util.AppendIfMissing(cachedLayer.Tags, scanTask.Tag)
	}
	return namespace, nil
}
