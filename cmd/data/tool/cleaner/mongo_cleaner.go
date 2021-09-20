package cleaner

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"gitlab.com/piccolo_su/vegeta/cmd/data/def"
	"gitlab.com/piccolo_su/vegeta/cmd/data/env"
	"gitlab.com/piccolo_su/vegeta/cmd/data/tool/conf"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/mongotools"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type MongoCleaner struct {
	db  *mongotools.DatabaseWrapper
	cnf *conf.MongoDumpConf
}

func NewMongoCleaner(db *mongotools.DatabaseWrapper, cnf *conf.MongoDumpConf) *MongoCleaner {
	return &MongoCleaner{
		db:  db,
		cnf: cnf,
	}
}

func (c *MongoCleaner) Clean(ctx context.Context, arg *def.CleanArg) error {
	collections, err := c.getAllCollections(ctx)
	if err != nil {
		return err
	}

	timeFilter := time.Now().Add(-time.Hour * 24 * time.Duration(arg.DaysOffset))
	var errMap = make(map[string]error)

	for _, collection := range collections {
		if err := c.dumpCollection(ctx, collection, timeFilter); err != nil {
			logging.GetLogger().Error().Msgf("dumpCollection %s, err:%s", collection, err.Error())
			errMap[collection] = err
			continue
		}
	}

	if len(errMap) == 0 {
		return nil
	}

	return makeError("mongo cleaner error", errMap)
}

func (c *MongoCleaner) getAllCollections(ctx context.Context) ([]string, error) {
	var allCollectionsCursor *mongo.Cursor
	getFunc := func() error {
		var err error
		allCollectionsCursor, err = c.db.Get().ListCollections(ctx, bson.M{})
		if err != nil {
			return fmt.Errorf("couldn't list monogo collections: %w", err)
		}
		return err
	}

	var err = util.WithRetry(getFunc, util.DefaultRetryConf)
	if err != nil {
		return nil, fmt.Errorf("getAllCollections fail, err:%w", err)
	}

	var collectionInfos []bson.D
	err = allCollectionsCursor.All(ctx, &collectionInfos)
	if err != nil {
		return nil, fmt.Errorf("decode allCollectionsCursor fail: %w", err)
	}

	var collections = make([]string, 0, len(collectionInfos))
	for _, collectionInfo := range collectionInfos {
		col, ok := collectionInfo.Map()["name"]
		if !ok {
			continue
		}

		colName, ok := col.(string)
		if !ok || colName == "" {
			continue
		}

		var excluded bool
		for _, excludedCol := range c.cnf.ExcludedCollections {
			if excludedCol == colName {
				excluded = true
				break
			}
		}

		if excluded || strings.HasPrefix(colName, "system.") {
			continue
		}

		collections = append(collections, colName)
	}

	return collections, nil
}

const (
	mongoInterval = time.Millisecond * 200
)

func (c *MongoCleaner) dumpCollection(ctx context.Context, collection string, timeFilter time.Time) error {
	dumpItem := &conf.DumpItem{
		Name:      collection,
		TimeField: c.cnf.TimeField,
		DataDir:   path.Join(c.cnf.BaseDir, collection),
		Batch:     c.cnf.Batch,
	}
	targetPath, tmpPath, err := initDumpInfo(dumpItem, timeFilter)
	if err != nil {
		return err
	}

	fileExist, err := checkFileExists(targetPath)
	if err != nil {
		return err
	}

	if fileExist {
		logging.GetLogger().Warn().Msgf("dump file:%s already exists", targetPath)
		return nil
	}

	var targetFile *os.File
	defer func() {
		clearDumpInfo(targetFile, tmpPath)
	}()

	for {
		hasData, err := mongoExport(ctx, dumpItem, timeFilter, tmpPath)
		if err != nil {
			return err
		}

		if !hasData {
			return nil
		}

		if targetFile == nil {
			targetFile, err = os.OpenFile(targetPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err != nil {
				return err
			}
		}

		err = mergeDumpFile(tmpPath, targetFile)
		if err != nil {
			return err
		}

		err = clearMongoData(ctx, c.db, dumpItem, timeFilter)
		if err != nil {
			return err
		}

		time.Sleep(mongoInterval)
	}
}

func mongoExport(ctx context.Context, collection *conf.DumpItem, timeFilter time.Time, tmpPath string) (hasData bool, err error) {
	var mongoURI string
	mongoUsername := util.GetEnvWithDefault(env.MongoUsername, env.DefaultMongoUsername)
	mongoPassword := util.GetEnvWithDefault(env.MongoPassword, "")
	mongoEndpoint := util.GetEnvWithDefault(env.MongoEndpoint, env.DefaultMongoEndpoint)
	mongoDatabase := util.GetEnvWithDefault(env.MongoDatabase, env.DefaultMongoDatabase)
	mongoReadReference := util.GetEnvWithDefault(env.MongoReadPreference, env.DefaultMongoReadPreference)

	if mongoUsername != "" && mongoPassword != "" {
		mongoURI = fmt.Sprintf("mongodb://%s:%s@%s/%s", mongoUsername, mongoPassword, mongoEndpoint, mongoDatabase)
	} else {
		mongoURI = fmt.Sprintf("mongodb://%s/%s", mongoEndpoint, mongoDatabase)
	}

	cmd := exec.CommandContext(ctx, "mongoexport",
		fmt.Sprintf("--collection=%s", collection.Name),
		"--noHeaderLine",
		fmt.Sprintf("--uri=\"%s\"", mongoURI),
		fmt.Sprintf("--out=%s", tmpPath),
		fmt.Sprintf("--readPreference=%s", mongoReadReference),
		fmt.Sprintf("--limit=%d", collection.Batch),
		fmt.Sprintf("--sort={\"%s\": 1, \"_id\":1}", collection.TimeField),
		fmt.Sprintf(`--query={"%s": {"$lt": {"$date": "%s"}}}`, collection.TimeField, timeFilter.UTC().Format("2006-01-02T15:04:05.000Z")),
	)

	logging.GetLogger().Info().Msgf("mongoexport cmd:%s", cmd.String())
	stdout, stderr, err := util.ExecuteCmd(cmd)
	if err != nil {
		return false, fmt.Errorf("execute command fail, err:%s, stderr:%s", err.Error(), stderr)
	}

	logging.GetLogger().Info().Msgf("mongoexport successfully, stdout:%s, stderr:%s", stdout, stderr)
	return !strings.Contains(stderr, "exported 0 record"), nil
}

func clearMongoData(ctx context.Context, mongodb *mongotools.DatabaseWrapper, collection *conf.DumpItem, timeFilter time.Time) error {
	clearFunc := func() error {
		filter := bson.M{collection.TimeField: bson.M{"$lt": util.GetMillisecondTime(timeFilter).UTC()}}
		findOptions := &options.FindOptions{}
		cursor, err := mongodb.Get().Collection(collection.Name).Find(ctx, filter,
			findOptions.
				SetSort(bson.D{{Key: collection.TimeField, Value: 1}, {Key: "_id", Value: 1}}).
				SetLimit(collection.Batch).
				SetProjection(bson.M{"_id": 1}))
		if err != nil {
			return fmt.Errorf("get record fail:%w", err)
		}

		var records []struct {
			ID primitive.ObjectID `bson:"_id"`
		}
		if err = cursor.All(ctx, &records); err != nil {
			logging.GetLogger().Error().Msgf("marshal fail, err:%s", err.Error())
			return err
		}

		if len(records) == 0 {
			logging.GetLogger().Warn().Msgf("empty records")
			return nil
		}

		var toBeDeleted = make([]primitive.ObjectID, 0, len(records))
		for _, record := range records {
			toBeDeleted = append(toBeDeleted, record.ID)
		}

		deleteFilter := bson.M{"_id": bson.M{"$in": toBeDeleted}}
		_, err = mongodb.Get().Collection(collection.Name).DeleteMany(ctx, deleteFilter)
		if err != nil {
			logging.GetLogger().Error().Msgf("delete documents fail, colName:%s, err:%s", collection.Name, err.Error())
			return fmt.Errorf("cannot delete mongo documents, collection:%s, err:%w", collection.Name, err)
		}

		logging.GetLogger().Info().Msgf("clear data successfully, len:%d", len(toBeDeleted))
		return nil
	}

	return util.WithRetry(clearFunc, util.DefaultRetryConf)
}
