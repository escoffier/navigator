package component

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"

	"gitlab.com/piccolo_su/vegeta/pkg/flag"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/redclair"
)

// RedClair ...
type RedClair struct {
	ctx     context.Context
	mongodb *mongo.Database
	meta    *redclair.MetaScanData

	cveWhitelist      map[string]struct{}
	ignoreRegExp      *regexp.Regexp
	sensitivePatterns []redclair.SecretPattern

	scanTasksChan chan model.ScanTask
}

// NewRedClair creates the instance of RedClair
func NewRedClair(ctx context.Context, clairOpts *flag.ClairOpts, db *mongo.Database) *RedClair {
	return &RedClair{
		ctx:           ctx,
		mongodb:       db,
		meta:          redclair.InitConfigureFiles(clairOpts),
		scanTasksChan: make(chan model.ScanTask, 1000),
	}
}

// Run runs the RedClair instance
func (rc *RedClair) Run(ctx context.Context) {
	log.Info().
		Str("url", rc.meta.URL).
		Msg("[Scanner] Scanner service starting...")

	rc.ignoreRegExp = redclair.InitializeRedclair(rc.meta)

	// Init sensitive pattern
	rc.sensitivePatterns = rc.meta.SecretPatternList[:0]
	for _, i := range rc.meta.SecretPatternList {
		i.Regex = regexp.MustCompile(i.Value)
		sensitivePatterns = append(sensitivePatterns, i)
		log.Debug().
			Str("type", i.Type).
			Str("description", i.Description).
			Msg("[sensitive patterns]")
	}

	// Init CVE whitelist
	rc.cveWhitelist = make(map[string]struct{}, len(rc.meta.CveWhiteList))
	for _, v := range rc.meta.CveWhiteList {
		log.Debug().
			Str("cve", v.CVE).
			Msg("[whitelist cve]")
		rc.cveWhitelist[v.CVE] = struct{}{}
	}
	log.Info().Msgf("%+v\n", rc.cveWhitelist)

	// Set scanner environment
	err := os.Setenv("DOCKER_API_VERSION", "1.38")
	if err != nil {
		log.Error().
			Err(err).
			Msg("error in setting DOCKER_API_VERSION")
	}

	// we can have multiple workers here
loop:
	for {
		select {
		case scanTask := <-rc.scanTasksChan:
			rc.processScanTask(scanTask)
		case <-ctx.Done():
			break loop
		}
	}
}

func (rc *RedClair) processScanTask(scanTask model.ScanTask) {
	// If scanTask.ForceScan

	// handle scanTask here
	vulnReport, fileSignatures, software, err := redclair.Scan(
		redclair.ScannerConfig{
			Experimental:       true,
			ImageName:          scanTask.GetNameTag(),
			Whitelist:          redclair.VulnerabilitiesWhitelist{},
			ClairURL:           fmt.Sprintf("http://%s:%d", rc.meta.RemoteURL, rc.meta.RemotePort),
			ScannerIP:          rc.meta.URL,
			ScannerPort:        rc.meta.Port,
			WhitelistThreshold: "Unknown",
			ReportAll:          true,
		},
		"",
		true,
		rc.ignoreRegExp,
	)
	if err != nil {
		log.Error().
			Err(err).
			Msg("error in redclair.Scan()")
	}

	scanTask.ScanReport = model.ScanReport{
		Vulns:    *vulnReport,
		Files:    fileSignatures,
		Software: software,
	}

	filter := bson.M{"_id": scanTask.ID}
	update := bson.M{"$set": scanTask}

	ctx, cancel := context.WithTimeout(rc.ctx, 10*time.Second)
	defer cancel()
	_, err = rc.mongodb.Collection(model.ScanTasksCollection).UpdateOne(ctx, filter, update)
	if err != nil {
		log.Error().
			Err(err).
			Msg("error in updating task in Mongo")
	}
}

// AddScanTask adds ScanTask to the internal channel
func (rc *RedClair) AddScanTask(task model.ScanTask) {
	rc.scanTasksChan <- task
}
