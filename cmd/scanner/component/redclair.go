package component

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"

	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/flag"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/redclair"
	"gitlab.com/piccolo_su/vegeta/pkg/util"

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
	cacheInvalidatorInterval = time.Hour * 2
	maxLayerScanRetires      = 3
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

	cond          *sync.Cond
	numRunning    int
	wantsToUpdate bool
}

// NewRedClair creates the instance of RedClair
func NewRedClairService(ctx context.Context, clairOpts *flag.ClairOpts, db *mongo.Database, rc *redis.Client) (*RedClairService, error) {
	redclairEng, err := redclair.NewRedclair(clairOpts, db)
	if err != nil {
		return nil, err
	}
	m := sync.Mutex{}
	c := sync.NewCond(&m)
	return &RedClairService{
		ctx:                     ctx,
		mongodb:                 db,
		redisClient:             rc,
		scanTasksChan:           make(chan model.ScanTask, 1000),
		numWorkers:              clairOpts.NumWorkers,
		redclairEngine:          redclairEng,
		skipRegistryTLSVerify:   clairOpts.SkipRegistryTLSVerify,
		clairDBConnectionString: clairOpts.PostgresConnectionString,
		cond:                    c,
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
	go rcSvc.cacheInvalidatorRun(ctx, &wg)

	for i := 0; i < rcSvc.numWorkers; i++ {
		wg.Add(1)
		go rcSvc.workerRun(ctx, i, &wg)
	}
	wg.Wait()
	log.Info().Msg("All Redclair workers finished")
}

// AddScanTask adds ScanTask to the internal channel
func (rcSvc *RedClairService) AddScanTask(task model.ScanTask) {
	rcSvc.scanTasksChan <- task
}

// ForceInvalidateCache flushes redis cache and reinitializes it
func (rcSvc *RedClairService) ForceInvalidateCache(ctx context.Context) error {
	_, err := rcSvc.redisClient.FlushAll(ctx).Result()
	if err != nil {
		// https://stackoverflow.com/a/59189742
		// Redis official Helm chart by default disables FLUSHDB and FLUSHALL commands
		// In this case, it is not specified in any of the redis.conf inside the containers, so you need to specify it in your Redis YAML:
		// 	master:
		// 	  disableCommands: []
		return NewRedisError(http.StatusInternalServerError, fmt.Errorf("Failed to flush redis "+
			"(if using redis official helm chart, check master.disableCommands): %w", err))
	}

	err = rcSvc.updateLayerCache(ctx)
	if err != nil {
		return NewAnError(http.StatusInternalServerError, fmt.Errorf("Failed to recreate cache after invalidation: %w", err))
	}

	return nil
}

func (rcSvc *RedClairService) cacheInvalidatorRun(ctx context.Context, wg *sync.WaitGroup) {
	log.Info().Msg("Started cache invalidator worker")

	defer wg.Done()
	rcSvc.updateLayerCache(ctx)
	ticker := time.NewTicker(cacheInvalidatorInterval)
loop:
	for {
		select {
		case <-ticker.C:
			log.Info().Msg("Cache invalidator received request to update layer cache")

			rcSvc.cond.L.Lock()
			{
				for rcSvc.numRunning > 0 {
					rcSvc.wantsToUpdate = true
					log.Info().Bool("wantsToUpdate", rcSvc.wantsToUpdate).Int("numRunning", rcSvc.numRunning).Msg("Cache invalidator waiting")
					rcSvc.cond.Wait()
					log.Info().Bool("wantsToUpdate", rcSvc.wantsToUpdate).Int("numRunning", rcSvc.numRunning).Msg("Cache invalidator waking up")
				}

				log.Info().Bool("wantsToUpdate", rcSvc.wantsToUpdate).Int("numRunning", rcSvc.numRunning).Msg("Cache invalidator updating layer cache")
				err := rcSvc.updateLayerCache(ctx)
				if err != nil {
					log.Error().Err(err).Msg("Cache invalidator - updateLayerCache failed")
				}

				rcSvc.wantsToUpdate = false
				log.Info().Bool("wantsToUpdate", rcSvc.wantsToUpdate).Int("numRunning", rcSvc.numRunning).Msg("Cache invalidator resuming workers after clair update")
			}
			rcSvc.cond.L.Unlock()

			rcSvc.cond.Broadcast()
			log.Info().Msg("Cache invalidator done")
		case <-ctx.Done():
			break loop
		}
	}
	log.Info().Msg("Shutting down Redclair cache invalidator worker")
}

func (rcSvc *RedClairService) workerRun(ctx context.Context, id int, wg *sync.WaitGroup) {
	defer wg.Done()

	workerSublogger := log.With().Int("worker-id", id).Logger()
	ctx = workerSublogger.WithContext(ctx)

	zerolog.Ctx(ctx).Info().Msg("Started Redclair worker")
loop:
	for {
		select {
		case scanTask := <-rcSvc.scanTasksChan:
			zerolog.Ctx(ctx).Info().Msg("Received scan task")

			rcSvc.cond.L.Lock()
			{
				for rcSvc.wantsToUpdate {
					zerolog.Ctx(ctx).Info().Bool("wantsToUpdate", rcSvc.wantsToUpdate).Int("numRunning", rcSvc.numRunning).Msg("Waiting")
					rcSvc.cond.Wait()
					log.Info().Bool("wantsToUpdate", rcSvc.wantsToUpdate).Int("numRunning", rcSvc.numRunning).Msg("Waking up")
				}
				rcSvc.numRunning++
				zerolog.Ctx(ctx).Info().Bool("wantsToUpdate", rcSvc.wantsToUpdate).Int("numRunning", rcSvc.numRunning).Msg("Got cond, incremented numRunning")
			}
			rcSvc.cond.L.Unlock()

			zerolog.Ctx(ctx).Info().Msg("Starting scanning")
			rcSvc.processScanTask(ctx, scanTask)
			zerolog.Ctx(ctx).Info().Msg("Finished scanning")

			rcSvc.cond.L.Lock()
			{
				rcSvc.numRunning--
				zerolog.Ctx(ctx).Info().Int("numRunning", rcSvc.numRunning).Msg("Decremented numRunning")
			}
			rcSvc.cond.L.Unlock()

			rcSvc.cond.Signal()
			zerolog.Ctx(ctx).Info().Msg("Ready to accept new tasks")
		case <-ctx.Done():
			break loop
		}
	}
	zerolog.Ctx(ctx).Info().Msg("Shutting down Redclair worker")
}

func (rcSvc *RedClairService) getUpdatedAt(ctx context.Context) (int64, error) {
	lastUpdateTimeStr, err := rcSvc.redisClient.Get(ctx, "DBupdate").Result()
	if err == redis.Nil {
		log.Info().Msg("Haven't cached DB last update yet")
		return int64(0), nil
	} else if err != nil {
		return int64(0), fmt.Errorf("Error getting DB update time from cache: %w", err)
	}
	lastUpdateTime, err := strconv.ParseInt(lastUpdateTimeStr, 10, 64)
	if err != nil {
		return int64(0), fmt.Errorf("Error converting DBupdateTime from cache to int64: %w", err)
	}
	return lastUpdateTime, nil
}

func (rcSvc *RedClairService) getVulnerabilityUpdatedAt(ctx context.Context) (string, error) {
	lastUpdateVulnerability, err := rcSvc.redisClient.Get(ctx, "lastUpdateVulnerability").Result()
	if err == redis.Nil {
		log.Info().Msg("Haven't cached DB vulnerability last update yet")
		return "", nil
	} else if err != nil {
		return "", fmt.Errorf("Error getting DB vulnerability update time from cache: %w", err)
	}
	return lastUpdateVulnerability, nil
}

func (rcSvc *RedClairService) updateLayerCache(ctx context.Context) error {
	db, err := sql.Open("postgres", rcSvc.clairDBConnectionString)
	if err != nil {
		return fmt.Errorf("Failed to open Clair DB connection: %w", err)
	}
	defer db.Close()

	var lastUpdate model.DBUpdateTime
	lastUpdateQuery := "SELECT value FROM keyvalue WHERE key='updater/last'"
	err = db.QueryRow(lastUpdateQuery).Scan(&lastUpdate.Value)
	if err != nil {
		return fmt.Errorf("Failed to get last update time from DB: %w", err)
	}

	lastUpdatedTime, err := rcSvc.getUpdatedAt(ctx)
	if err != nil {
		return fmt.Errorf("Failed to get last DB update time from cache: %w", err)
	}

	if lastUpdatedTime < lastUpdate.Value {
		_, err := rcSvc.redisClient.Set(ctx, "DBupdate", strconv.FormatInt(lastUpdate.Value, 10), redis.KeepTTL).Result()
		if err != nil {
			return fmt.Errorf("Cannot persist DB update time to cache: %w", err)
		}
		log.Info().Msg("DB update time successfully persisted in cache")
	}

	namespacesToRemoveFromCache := make([]string, 0)

	timeStrLastVulnerabilityUpdate, err := rcSvc.getVulnerabilityUpdatedAt(ctx)
	if err != nil {
		return fmt.Errorf("Failed to get last DB vulnerability update time from cache: %w", err)
	}
	if timeStrLastVulnerabilityUpdate != "" {
		err = rcSvc.appendNewVulnerabilities(ctx, db, timeStrLastVulnerabilityUpdate, &namespacesToRemoveFromCache)
		if err != nil {
			return fmt.Errorf("Failed to get new vulnerabilities from DB: %w", err)
		}
	}

	if timeStrLastVulnerabilityUpdate != "" {
		// TODO: Below is not tested
		err = rcSvc.appendRemovedVulnerabilities(ctx, db, timeStrLastVulnerabilityUpdate, &namespacesToRemoveFromCache)
		if err != nil {
			return fmt.Errorf("Failed to get fixed vulnerabilities from DB: %w", err)
		}
	}

	err = rcSvc.cacheLastVulnerabilityUpdateTime(ctx, db)
	if err != nil {
		return fmt.Errorf("Failed to persist last vulnerability update time in cache: %w", err)
	}

	err = rcSvc.invalidateCacheEntries(ctx, namespacesToRemoveFromCache)
	if err != nil {
		return fmt.Errorf("Failed to invalidate cache entries: %w", err)
	}

	return nil
}

func (rcSvc *RedClairService) invalidateCacheEntries(ctx context.Context, namespacesToRemoveFromCache []string) error {
	redisCtx, redisCtxCancel := context.WithTimeout(ctx, redisCleanupTimeout)
	defer redisCtxCancel()
	for _, namespaceToRemove := range namespacesToRemoveFromCache {
		iter := rcSvc.redisClient.Scan(redisCtx, 0, namespaceToRemove+"*", 0).Iterator()
		if err := iter.Err(); err != nil {
			return fmt.Errorf("Failed to iterate over cache entries: %w", err)
		}
		for iter.Next(redisCtx) {
			layerToRemove := iter.Val()
			err := rcSvc.redisClient.Del(redisCtx, layerToRemove).Err()
			if err != nil {
				return fmt.Errorf("Failed to remove layer from cache: %w", err)
			} else {
				log.Info().Str("digest", layerToRemove).Msg("Successfully removed from cache")
			}
		}
	}
	return nil
}

func (rcSvc *RedClairService) cacheLastVulnerabilityUpdateTime(ctx context.Context, db *sql.DB) error {
	var dbVulnerabilityUpdateTime model.DBVulnerabilityUpdateTime
	lastUpdateVulnerabilityQuery := "SELECT max(created_at) from vulnerability"
	err := db.QueryRow(lastUpdateVulnerabilityQuery).Scan(&dbVulnerabilityUpdateTime.MaxCreatedAt)
	if err != nil {
		return fmt.Errorf("Failed to get vulnerability update time: %w", err)
	}
	_, err = rcSvc.redisClient.Set(ctx, "lastUpdateVulnerability", dbVulnerabilityUpdateTime.MaxCreatedAt, redis.KeepTTL).Result()
	if err != nil {
		return fmt.Errorf("Cannot persist DB vulnerability update time to cache: %w", err)
	}
	log.Info().Str("vulnerabilityLastUpdateTime", dbVulnerabilityUpdateTime.MaxCreatedAt).Msg("DB vulnerability update time successfully persisted in cache")
	return nil
}

func (rcSvc *RedClairService) appendRemovedVulnerabilities(ctx context.Context, db *sql.DB, timeStrOfLastVulnerabilityUpdate string, namespacesToRemoveFromCache *[]string) error {
	removedVulnerabilitiesQuery := fmt.Sprintf(`
		select 
			a.name, c.name as namespace 
		from (
			select 
				name, 
				namespace_id, 
				max(
					CASE WHEN deleted_at IS NULL 
					THEN timestamp '9999-01-01 00:00:00.000000+00' 
					ELSE deleted_at END
				) as deleted_at 
			from 
				vulnerability 
			where 
				created_at > timestamp '%s' 
			group by 
				namespace_id, name
		) as a 
		left join (
			select
				name, 
				namespace_id, 
				max(
					CASE WHEN deleted_at IS NULL
					THEN timestamp '9999-01-01 00:00:00.000000+00' 
					ELSE deleted_at END
				) as deleted_at 
			from 
				vulnerability
			where 
				created_at <= timestamp '%s' 
			group by 
				namespace_id, name
		) as b 
		on a.name=b.name and a.namespace_id=b.namespace_id 
		left join 
			namespace c 
		on a.namespace_id=c.id 
		where 
			b.deleted_at = timestamp '9999-01-01 00:00:00.000000+00' 
			and a.deleted_at != timestamp '9999-01-01 00:00:00.000000+00';`, timeStrOfLastVulnerabilityUpdate, timeStrOfLastVulnerabilityUpdate)
	vulnerabilityEntry := model.DBVulnerabilityEntry{}
	rows, err := db.Query(removedVulnerabilitiesQuery)
	err = rows.Err()
	if err != nil {
		return fmt.Errorf("Failed to get removed vulnerability entries: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		err := rows.Scan(&vulnerabilityEntry.Name, &vulnerabilityEntry.NameSpace)
		if err != nil {
			return fmt.Errorf("Failed to get removed vulnerability entry: %w", err)
		} else {
			*namespacesToRemoveFromCache = util.AppendIfMissing(*namespacesToRemoveFromCache, vulnerabilityEntry.NameSpace)
		}
	}
	return nil
}

func (rcSvc *RedClairService) appendNewVulnerabilities(ctx context.Context, db *sql.DB, timeStrOfLastVulnerabilityUpdate string, namespacesToRemoveFromCache *[]string) error {
	newVulnerabilitiesQuery := fmt.Sprintf(`
		select 
			a.name, c.name as namespace 
		from (
			select 
				distinct name, namespace_id 
			from 
				vulnerability 
			where 
				created_at > timestamp '%s'
		) as a
		left join (
			select 
				distinct name, namespace_id 
			from 
				vulnerability
			where 
				created_at <= timestamp '%s'
		) as b 
		on a.name = b.name and a.namespace_id = b.namespace_id 
		left join 
			namespace c 
		on a.namespace_id = c.id 
		where 
			b.name is null;
	`, timeStrOfLastVulnerabilityUpdate, timeStrOfLastVulnerabilityUpdate)
	vulnerabilityEntry := model.DBVulnerabilityEntry{}
	rows, err := db.Query(newVulnerabilitiesQuery)
	err = rows.Err()
	if err != nil {
		return fmt.Errorf("Failed to get new vulnerability entries: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		err := rows.Scan(&vulnerabilityEntry.Name, &vulnerabilityEntry.NameSpace)
		if err != nil {
			return fmt.Errorf("Failed to get new vulnerability entry: %w", err)
		} else {
			*namespacesToRemoveFromCache = util.AppendIfMissing(*namespacesToRemoveFromCache, vulnerabilityEntry.NameSpace)
		}
	}
	return nil
}

func (rcSvc *RedClairService) processScanTask(ctx context.Context, scanTask model.ScanTask) {
	scanCtx, scanCtxCancel := context.WithTimeout(ctx, scanOneTimeout)
	defer scanCtxCancel()

	username := ""
	password := ""
	if scanTask.Authorization != "" {
		var err error
		username, password, err = rcSvc.decodeUsernamePassword(scanTask)
		if err != nil {
			rcSvc.logAndUpdateMongoStatus(ctx, scanTask, model.ScanStatusFailed, "Couldn't decode username and password", err)
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
		rcSvc.logAndUpdateMongoStatus(ctx, scanTask, model.ScanStatusFailed, "Couldn't initialize docker registry client", err)
		return
	}

	// TODO: Should we allow for v1?
	version := "v2"
	layers, err := rcSvc.readManifest(ctx, version, hub, scanTask)
	if err != nil {
		rcSvc.logAndUpdateMongoStatus(ctx, scanTask, model.ScanStatusFailed, "Couldn't read manifest", err)
		return
	}

	currentlyCachedLayers, toScan, err := rcSvc.getCachedGraph(ctx, layers, scanTask)
	if err != nil {
		rcSvc.logAndUpdateMongoStatus(ctx, scanTask, model.ScanStatusFailed, "Couldn't get cache graph", err)
		return
	}

	for i := range toScan {
		err := rcSvc.processLayer(scanCtx, hub, scanTask, &currentlyCachedLayers, toScan[i])
		if err != nil {
			switch err.(type) {
			case ClairUnprocessableLayerError:
				rcSvc.logAndUpdateMongoStatus(ctx, scanTask, model.ScanStatusUnprocessableEntity, "Error occured while scanning layers", err)
			default:
				rcSvc.logAndUpdateMongoStatus(ctx, scanTask, model.ScanStatusFailed, "Error occured while scanning layers", err)
			}
			return
		}
	}

	zerolog.Ctx(ctx).Info().Msg("Redclair scan finished, processed all layers")

	report := &model.ScanReport{}
	vulns := make([]redclair.VulnerabilityInfo, 0)
	sensitives := make([]redclair.Sensitive, 0)
	perLayerReport := make(map[string]redclair.VulnerabilityLayerReport)
	for layerNo, digest := range layers {
		cachedLayer, err := rcSvc.getCachedEntry(scanCtx, digest, currentlyCachedLayers)
		if err != nil {
			rcSvc.logAndUpdateMongoStatus(ctx, scanTask, model.ScanStatusFailed, "Failed to get entries from cache from just-finished scan", err)
			return
		}

		report.Files = append(report.Files, cachedLayer.ScanReport.Files...)
		report.Software = append(report.Software, cachedLayer.ScanReport.Software...)
		sensitives = append(sensitives, cachedLayer.ScanReport.Sensitive...)
		addedVulns := append([]redclair.VulnerabilityInfo(nil), cachedLayer.ScanReport.VulnsAdded...)
		util.SortVulnsBySeverityAndStuff(addedVulns, false)
		removedVulns := append([]redclair.VulnerabilityInfo(nil), cachedLayer.ScanReport.VulnsRemoved...)
		util.SortVulnsBySeverityAndStuff(removedVulns, false)
		// https://jira.mongodb.org/browse/GODRIVER-1190 - but still not part of library
		perLayerReport[strconv.Itoa(layerNo)] = redclair.VulnerabilityLayerReport{
			LayerDigest:            digest,
			VulnerabilitiesAdded:   addedVulns,
			VulnerabilitiesRemoved: removedVulns,
			Sensitives:             cachedLayer.ScanReport.Sensitive,
		}

		currentVulns := vulns[:0]
		for _, v := range vulns {
			remove := false
			for _, vv := range cachedLayer.ScanReport.VulnsRemoved {
				if v.CVE == vv.CVE {
					remove = true
				}
			}
			if remove {
				continue
			} else {
				currentVulns = append(currentVulns, v)
			}
		}
		for _, v := range cachedLayer.ScanReport.VulnsAdded {
			currentVulns = append(currentVulns, v)
		}

		vulns = currentVulns
	}
	report.Vulns = redclair.VulnerabilityReport{
		Repository:      scanTask.Repository,
		Tag:             scanTask.Tag,
		Digest:          scanTask.ImageDigest,
		Unapproved:      []string{},
		Vulnerabilities: vulns,
		Sensitives:      sensitives,
		PerLayerReport:  perLayerReport,
	}
	scanTask.ScanReport = *report
	rcSvc.logAndUpdateMongoStatus(ctx, scanTask, model.ScanStatusSucceeded, "", nil)
}

func (rcSvc *RedClairService) processLayer(ctx context.Context, hub *registry.Registry, scanTask model.ScanTask, currentlyCachedLayers *map[string]*model.CachedLayer, digest string) error {
	layersBench := make([]*model.CachedLayer, 0)
	currLayer := (*currentlyCachedLayers)[digest]
	retryCounter := 0
	currentMaxScanRetries := maxLayerScanRetires
	for retryCounter <= currentMaxScanRetries {
		layerNamespace, vulnInfo, fileSignatures, software, sensitive, err := rcSvc.redclairEngine.ScanLayer(
			ctx,
			hub,
			currLayer.Digest,
			currLayer.Parent,
			scanTask.Repository,
		)
		if err != nil {
			// TODO: bug prone if we add more error wrapping in the future. Prefer to use errors.As().
			switch err.(type) {
			default:
				zerolog.Ctx(ctx).Error().Err(err).Int("retryCounter", retryCounter).Str("layerDigest", currLayer.Digest).Msg("Redclair scan failed. Retrying")
				time.Sleep(retryInterval)
				retryCounter++
			case ClairUnprocessableLayerError:
				return err
			case ClairMissingParentLayerError:
				zerolog.Ctx(ctx).Info().Msg("Clair missing parent layer scan. Trying to scan parent next")
				layersBench = append(layersBench, currLayer)
				parentLayerDigest := currLayer.Parent
				currentMaxScanRetries = maxLayerScanRetires
				currLayer, err = rcSvc.getParentLayerFromCache(ctx, parentLayerDigest, *currentlyCachedLayers)
				if err != nil {
					zerolog.Ctx(ctx).Info().Str("layerDigest", currLayer.Digest).Msg("Couldn't get parent layer from cache")
					return err
				}
			}
		} else {
			zerolog.Ctx(ctx).Info().Str("layerDigest", currLayer.Digest).Msg("Clair scan successful")
			var vulnInfoAdded, vulnInfoRemoved []redclair.VulnerabilityInfo
			if currLayer.Parent == "" {
				vulnInfoAdded = vulnInfo
				vulnInfoRemoved = make([]redclair.VulnerabilityInfo, 0)
			} else {
				parentLayer, err := rcSvc.getParentLayerFromCache(ctx, currLayer.Parent, *currentlyCachedLayers)
				if err != nil {
					zerolog.Ctx(ctx).Info().Str("parentlayerDigest", currLayer.Parent).Str("layerDigest", currLayer.Digest).Msg("Couldn't get parent layer from cache")
					return err
				}
				vulnInfoAdded, vulnInfoRemoved, err = rcSvc.getLayerVulnDiff(parentLayer.ScanReport.Vulns, vulnInfo)
				if err != nil {
					zerolog.Ctx(ctx).Info().Str("parentlayerDigest", currLayer.Parent).Str("layerDigest", currLayer.Digest).Msg("Couldn't get layer diff between current and parent")
					return err
				}
			}
			scanWorkerResult := &model.ScanWorkerReport{
				Vulns:        vulnInfo,
				VulnsAdded:   vulnInfoAdded,
				VulnsRemoved: vulnInfoRemoved,
				Files:        fileSignatures,
				Software:     software,
				Sensitive:    sensitive,
			}
			err = rcSvc.updateCacheEntry(ctx, scanWorkerResult, currentlyCachedLayers, currLayer.Digest, layerNamespace)
			if len(layersBench) > 0 {
				currLayer = layersBench[len(layersBench)-1]
				layersBench = layersBench[:len(layersBench)-1]
				retryCounter = 0
				currentMaxScanRetries = maxLayerScanRetires
			} else {
				return nil
			}
		}
	}
	if retryCounter > maxLayerScanRetires {
		return fmt.Errorf("Max retries reached for a single layer")
	}
	return nil
}

func (rcSvc *RedClairService) getLayerVulnDiff(parentFullVulns []redclair.VulnerabilityInfo, currFullVulns []redclair.VulnerabilityInfo) ([]redclair.VulnerabilityInfo, []redclair.VulnerabilityInfo, error) {
	vulnLayerAdded := make([]redclair.VulnerabilityInfo, 0)
	vulnLayerRemoved := make([]redclair.VulnerabilityInfo, 0)
	sort.Slice(parentFullVulns, func(i, j int) bool {
		return parentFullVulns[i].CVE < parentFullVulns[j].CVE
	})
	sort.Slice(currFullVulns, func(i, j int) bool {
		return currFullVulns[i].CVE < currFullVulns[j].CVE
	})
	parentIndex := 0
	currIndex := 0
	for currIndex < len(currFullVulns) {
		if parentIndex >= len(parentFullVulns) {
			vulnLayerAdded = append(vulnLayerAdded, currFullVulns[currIndex])
			currIndex++
			continue
		}
		if currFullVulns[currIndex].CVE < parentFullVulns[parentIndex].CVE {
			vulnLayerAdded = append(vulnLayerAdded, currFullVulns[currIndex])
			currIndex++
		} else if currFullVulns[currIndex].CVE > parentFullVulns[parentIndex].CVE {
			vulnLayerRemoved = append(vulnLayerRemoved, parentFullVulns[parentIndex])
			parentIndex++
		} else {
			currIndex++
			parentIndex++
		}
	}
	for parentIndex < len(parentFullVulns) {
		vulnLayerRemoved = append(vulnLayerRemoved, parentFullVulns[parentIndex])
		parentIndex++
	}
	return vulnLayerAdded, vulnLayerRemoved, nil
}

func (rcSvc *RedClairService) getCachedEntry(ctx context.Context, digest string, currentLayerCache map[string]*model.CachedLayer) (*model.CachedLayer, error) {
	iter := rcSvc.redisClient.Scan(ctx, 0, "*"+digest, 0).Iterator()
	if err := iter.Err(); err != nil {
		zerolog.Ctx(ctx).Err(err).Str("layerDigest", digest).Msg("Failed to iterate over cache entries")
		if currLayer, exists := currentLayerCache[digest]; exists {
			return currLayer, nil
		}
		return nil, fmt.Errorf("Layer exists neither in global, nor local cache")
	}
	if iter.Next(ctx) {
		v := iter.Val()
		cacheEntry, err := rcSvc.redisClient.Get(ctx, v).Result()
		if err == redis.Nil {
			// Such situation could happen, if in the meantime the cache cleaning process has removed
			// this entry (because the clair database has updated for tree containing this layer).
			// In such case return the local cache result.
			zerolog.Ctx(ctx).Info().Str("layerDigest", digest).Msg("Cached entry cleared during scanning the image. Taking the local cache entry")
			if currLayer, exists := currentLayerCache[digest]; exists {
				return currLayer, nil
			}
			return nil, fmt.Errorf("Layer exists neither in global, nor local cache")
		} else if err != nil {
			zerolog.Ctx(ctx).Err(err).Str("layerDigest", digest).Msg("Error getting layer from cache")
			if currLayer, exists := currentLayerCache[digest]; exists {
				return currLayer, nil
			}
			return nil, fmt.Errorf("Layer exists neither in global, nor local cache")
		} else {
			cachedLayer := &model.CachedLayer{
				Digest: digest,
			}
			err = json.Unmarshal([]byte(cacheEntry), cachedLayer)
			if err != nil {
				zerolog.Ctx(ctx).Info().Str("layerDigest", digest).Msg("Couldn't unmarshal layer entry from cache")
				if currLayer, exists := currentLayerCache[digest]; exists {
					return currLayer, nil
				}
				return nil, fmt.Errorf("Layer exists neither in global, nor local cache")
			}
			return cachedLayer, nil
		}
	} else {
		zerolog.Ctx(ctx).Info().Str("layerDigest", digest).Msg("Cached entry cleared during scanning the image. Taking the local cache entry")
		if currLayer, exists := currentLayerCache[digest]; exists {
			return currLayer, nil
		}
		return nil, fmt.Errorf("Layer exists neither in global, nor local cache")
	}
}

func (rcSvc *RedClairService) updateCacheEntry(ctx context.Context, scanResult *model.ScanWorkerReport, currentLayerCache *map[string]*model.CachedLayer, layer string, namespace string) error {
	if _, exists := (*currentLayerCache)[layer]; !exists {
		return fmt.Errorf("Layer exists neither in global, nor local cache")
	}
	(*currentLayerCache)[layer].ScanReport = scanResult
	(*currentLayerCache)[layer].NameSpace = namespace
	_, err := rcSvc.redisClient.Get(ctx, namespace+"_"+layer).Result()
	if err == redis.Nil {
		zerolog.Ctx(ctx).Info().Str("layerDigest", layer).Msg("Persisting in cache")
		cacheEntry, err := json.Marshal((*currentLayerCache)[layer])
		if err != nil {
			zerolog.Ctx(ctx).Err(err).Str("layerDigest", layer).Msg("Layer could not be marshaled. Not persisting")
			return nil
		} else {
			redisCtx, redisCtxCancel := context.WithTimeout(ctx, redisTimeout)
			defer redisCtxCancel()
			_, err := rcSvc.redisClient.Set(redisCtx, namespace+"_"+layer, cacheEntry, redis.KeepTTL).Result()
			if err != nil {
				zerolog.Ctx(ctx).Error().Err(err).Str("layerDigest", layer).Msg("Layer could not be cached. Not persisting")
				return nil
			}
			zerolog.Ctx(ctx).Info().Str("layerDigest", layer).Msg("Layer successfully cached")
			return nil
		}
	} else if err != nil {
		zerolog.Ctx(ctx).Err(err).Str("layerDigest", layer).Msg("Error getting layer from cache. Not persisting")
		return nil
	}

	zerolog.Ctx(ctx).Info().Str("layerDigest", layer).Msg("Another worker recently scanned this layer. No need to persist")
	return nil
}

func (rcSvc *RedClairService) getParentLayerFromCache(ctx context.Context, parentLayer string, currentLayerCache map[string]*model.CachedLayer) (*model.CachedLayer, error) {
	iter := rcSvc.redisClient.Scan(ctx, 0, "*"+parentLayer, 0).Iterator()
	if err := iter.Err(); err != nil {
		zerolog.Ctx(ctx).Err(err).Str("layerDigest", parentLayer).Msg("Failed to iterate over cache entries")
		if currLayer, exists := currentLayerCache[parentLayer]; exists {
			return currLayer, nil
		}
		return nil, fmt.Errorf("Layer exists neither in global, nor local cache")
	}
	if iter.Next(ctx) {
		v := iter.Val()
		cacheEntry, err := rcSvc.redisClient.Get(ctx, v).Result()
		if err == redis.Nil {
			zerolog.Ctx(ctx).Info().Str("layerDigest", parentLayer).Msg("Weird...")
			if currLayer, exists := currentLayerCache[parentLayer]; exists {
				return currLayer, nil
			}
			return nil, fmt.Errorf("Layer exists neither in global, nor local cache")
		} else if err != nil {
			zerolog.Ctx(ctx).Err(err).Str("layerDigest", parentLayer).Msg("Error getting layer from cache")
			if currLayer, exists := currentLayerCache[parentLayer]; exists {
				return currLayer, nil
			}
			return nil, fmt.Errorf("Layer exists neither in global, nor local cache")
		} else {
			cachedLayer := &model.CachedLayer{
				Digest: parentLayer,
			}
			err = json.Unmarshal([]byte(cacheEntry), cachedLayer)
			if err != nil {
				zerolog.Ctx(ctx).Err(err).Str("layerDigest", parentLayer).Msg("Layer from cache could not be unmarshaled.")
				if currLayer, exists := currentLayerCache[parentLayer]; exists {
					return currLayer, nil
				}
				return nil, fmt.Errorf("Layer exists neither in global, nor local cache")
			} else {
				return cachedLayer, nil
			}
		}
	} else {
		zerolog.Ctx(ctx).Info().Str("layerDigest", parentLayer).Msg("Parent layer not found in cache")
		if currLayer, exists := currentLayerCache[parentLayer]; exists {
			return currLayer, nil
		}
		return nil, fmt.Errorf("Layer exists neither in global, nor local cache")
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

func (rcSvc *RedClairService) logAndUpdateMongoStatus(ctx context.Context, scanTask model.ScanTask, status, message string, originalErr error) {
	mongoCtx, mongoCtxCancel := context.WithTimeout(ctx, mongoTimeout)
	defer mongoCtxCancel()

	if originalErr != nil {
		zerolog.Ctx(ctx).Error().Err(originalErr).Msg(message)
		scanTask.Message = fmt.Sprintf("%s: %s", message, originalErr)
	}

	scanTask.FinishedAt = time.Now().Unix()
	scanTask.Status = status

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

func (rcSvc *RedClairService) getCachedGraph(ctx context.Context, layers []string, scanTask model.ScanTask) (map[string]*model.CachedLayer, []string, error) {
	currentLayerCache := make(map[string]*model.CachedLayer)
	toScan := make([]string, 0)
	var prevLayer string
	for i, layer := range layers {
		cachedLayer := &model.CachedLayer{
			Digest: layer,
		}
		iter := rcSvc.redisClient.Scan(ctx, 0, "*"+layer, 0).Iterator()
		if err := iter.Err(); err != nil {
			zerolog.Ctx(ctx).Err(err).Msg("Failed to get cache entry")
			currentLayerCache[layer] = cachedLayer
			toScan = append(toScan, layer)
		} else {
			if iter.Next(ctx) {
				v := iter.Val()
				cacheEntry, err := rcSvc.redisClient.Get(ctx, v).Result()
				if err == redis.Nil {
					zerolog.Ctx(ctx).Info().Str("layerDigest", layer).Msg("Layer not cached. Need to scan")
					toScan = append(toScan, layer)
				} else if err != nil {
					zerolog.Ctx(ctx).Err(err).Str("layerDigest", layer).Msg("Error getting layer from cache")
					toScan = append(toScan, layer)
				} else {
					err = json.Unmarshal([]byte(cacheEntry), cachedLayer)
					if err != nil {
						zerolog.Ctx(ctx).Err(err).Str("layerDigest", layer).Msg("Layer could not be unmarshaled.")
						toScan = append(toScan, layer)
					} else {
						zerolog.Ctx(ctx).Info().Str("layerDigest", layer).Msg("Layer cached. No need to scan")
					}
				}
				currentLayerCache[layer] = cachedLayer
				if i != 0 {
					currentLayerCache[layer].Parent = prevLayer
				} else {
					currentLayerCache[layer].ImageDigests = util.AppendIfMissing(cachedLayer.ImageDigests, layer)
					currentLayerCache[layer].Repositories = util.AppendIfMissing(cachedLayer.Repositories, scanTask.Repository)
					currentLayerCache[layer].Tags = util.AppendIfMissing(cachedLayer.Tags, scanTask.Tag)
				}
			} else {
				zerolog.Ctx(ctx).Info().Str("layerDigest", layer).Msg("Layer not cached. Need to scan")
				toScan = append(toScan, layer)
				currentLayerCache[layer] = cachedLayer
				if i != 0 {
					currentLayerCache[layer].Parent = prevLayer
				}
			}
		}
		prevLayer = layer
	}
	return currentLayerCache, toScan, nil
}

func (rcSvc *RedClairService) readManifest(ctx context.Context, version string, hub *registry.Registry, scanTask model.ScanTask) ([]string, error) {
	layers := make([]string, 0)
	if version == "v1" {
		manifest, err := hub.Manifest(scanTask.Repository, scanTask.ImageDigest)
		if err != nil {
			return []string{}, fmt.Errorf("Could not read docker V1 manifest: %w", err)
		}
		for _, layer := range manifest.Manifest.FSLayers {
			layerDigest := layer.BlobSum.String()
			layers = append([]string{layerDigest}, layers...)
		}
	} else if version == "v2" {
		manifest, err := hub.ManifestV2(scanTask.Repository, scanTask.ImageDigest)
		if err != nil {
			return []string{}, fmt.Errorf("Could not read docker V2 manifest: %w", err)
		}
		for _, layer := range manifest.Manifest.Layers {
			layerDigest := layer.Digest.String()
			layers = append(layers, layerDigest)
		}
	}
	return layers, nil
}
