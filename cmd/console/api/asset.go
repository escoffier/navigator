package api

import (
	"net/http"
	"time"

	"github.com/go-chi/chi"
	param "github.com/oceanicdev/chi-param"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo/options"

	"gitlab.com/piccolo_su/vegeta/pkg/locale"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
)

const (
	clusterAssetCol   = "cluster_asset"
	imageAssetCol     = "image_asset"
	containerAssetCol = "container_asset"
)

type clusterOverviewItem struct {
	Key       string    `json:"key"`
	Disabled  bool      `json:"disabled"`
	Name      string    `json:"name"`
	Owner     string    `json:"owner"`
	Namespace string    `json:"namespace"`
	Cluster   string    `json:"cluster"`
	Type      string    `json:"type"` //1.node 2.pod 3.service
	Title     string    `json:"title"`
	Status    int       `json:"status"`
	UpdatedAt time.Time `json:"updatedAt"`
	CreatedAt time.Time `json:"createdAt"`
	Desc      string    `json:"desc"`
	Tags      []string  `json:"tags,omitempty"`
}

type vulnerabilityOverviewItem struct {
	Key    string `json:"key"`
	Number int    `json:"number"`
}

type imageOverviewItem struct {
	Key                   string                      `json:"key"`
	Name                  string                      `json:"name"`
	Repo                  string                      `json:"repo"`
	Tag                   string                      `json:"tag"`
	Owner                 string                      `json:"owner"`
	Desc                  string                      `json:"desc"`
	CallNo                int                         `json:"callNo"`
	Status                int                         `json:"status"`
	Updated               time.Time                   `json:"updatedAt"`
	Created               time.Time                   `json:"createdAt"`
	Sha                   string                      `json:"sha"`
	VulnerabilityOverview []vulnerabilityOverviewItem `json:"vulnerabilities,omitempty"`
}

type asssetsContainerOverviewItem struct {
	Key       string    `json:"key"`
	Name      string    `json:"name"`
	Title     string    `json:"title"`
	Owner     string    `json:"owner"`
	CallNo    int       `json:"callNo"`
	Image     string    `json:"image"`
	ImageID   int       `json:"image_id"`
	Node      int       `json:"node"`
	Status    int       `json:"status"`
	UpdatedAt time.Time `json:"updatedAt"`
	CreatedAt time.Time `json:"createdAt"`
}

type clusterList []clusterOverviewItem
type imageList []imageOverviewItem
type containerList []asssetsContainerOverviewItem

func (api *api) restAsset() func(chi.Router) {
	return func(r chi.Router) {
		r.Get("/clusters", api.clusterAssets())
		r.Get("/images", api.imageAssets())
		r.Get("/containers", api.dockerAssets())
	}
}

// func filterList(vs assetList, f func(v assetOverviewItem) bool) assetList {
// 	vsf := assetList{}
// 	for _, v := range vs {
// 		if f(v) {
// 			vsf = append(vsf, v)
// 		}
// 	}

// 	return vsf
// }

/*
func filterByCondition(d assetsClusters, r *http.Request) assetsClusters {
	// filterList result by query parameter.
	// It can be replaced by
	queryType, err := param.QueryString(r, "type")
	origList := d.Assets
	var newList assetList
	if err == nil {
		newList = filterList(origList, func(v assetOverviewItem) bool {
			return v.Type == strings.ToUpper(queryType)
		})

		origList = newList
	}

	sort.Slice(origList, func(i, j int) bool {
		return origList[i].CreatedAt.After(origList[j].CreatedAt)
	})

	d.Assets = origList

	return d
}
*/

// @Summary Clusters Detail API
// @Description Get Different Type of Assets in Cluster
// @ID v1-assets-clusters
// @Produce json
// @Router /api/v1/assets/clusters [get]
func (api *api) clusterAssets() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var items clusterList
		var filter = bson.M{}
		assetType, err := param.QueryString(r, "type")
		if err == nil {
			filter = bson.M{"type": assetType}
		}

		offset, limit := api.getOffsetAndLimit(r)
		opts := options.Find()
		opts.SetSkip(offset)
		opts.SetLimit(limit)
		pickField := bson.M{"detail": 0}
		opts.SetProjection(pickField)
		ctx, cancel := api.getTimeoutCtx(15 * time.Second)
		defer cancel()
		coll := api.mongodb.Collection(clusterAssetCol)

		cur, err := coll.Find(ctx, filter, opts)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("Couldn't find document")
			response.InternalError(w, response.WithMessage(locale.Error(locale.MongoError, r)))
			return
		}
		defer cur.Close(ctx)

		for cur.Next(ctx) {
			//Create a value into which the single document can be decoded
			var elem clusterOverviewItem
			err := cur.Decode(&elem)
			if err != nil {
				logging.GetLogger().Error().Err(err).Msg("Couldn't decode document")
				response.InternalError(w, response.WithMessage(locale.Error(locale.MongoError, r)))
				return
			}
			items = append(items, elem)
		}

		docNum, err := coll.CountDocuments(ctx, filter)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("Couldn't count documents")
			response.InternalError(w, response.WithMessage(locale.Error(locale.MongoError, r)))
			return
		}

		response.Ok(w,
			response.WithItems(items),
			response.WithTotalItems(docNum),
			response.WithItemsPerPage(limit),
			response.WithStartIndex(offset))
	}
}

// @Summary Images Detail API
// @Description Get Different Type of Assets in Cluster
// @ID v1-assets-images
// @Produce json
// @Param name query string false "image name"
// @Param status query int false " status "
// @Param numberAbove query int false " reference low bound "
// @Param numberBelow query int false "reference high bound "
// @Param date query string false " last scan time "
// @Param repoName query string false "repo name"
// @Param sha query string false "image sha"
// @Router /api/v1/assets/images [get]
func (api *api) imageAssets() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var items imageList
		var filter = bson.M{}

		imageName, err := param.QueryString(r, "name")
		if err == nil {
			filter["name"] = imageName
		}

		status, err := param.QueryInt(r, "status")
		if err == nil {
			filter["status"] = status
		}

		repoName, err := param.QueryString(r, "repoName")
		if err == nil {
			filter["repo"] = repoName
		}

		sha, err := param.QueryString(r, "sha")
		if err == nil {
			filter["sha"] = sha
		}

		date, err := param.QueryString(r, "date")
		if err == nil {
			t, err := time.Parse("2006-1-2", date)
			if err == nil {
				filter["updated"] = bson.M{"$gte": t}
			}
		}

		offset, limit := api.getOffsetAndLimit(r)
		opts := options.Find()
		opts.SetSkip(offset)
		opts.SetLimit(limit)
		pickField := bson.M{"detail": 0}
		opts.SetProjection(pickField)

		ctx, cancel := api.getTimeoutCtx(15 * time.Second)
		defer cancel()
		coll := api.mongodb.Collection(imageAssetCol)

		cur, err := coll.Find(ctx, filter, opts)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("Couldn't find document")
			response.InternalError(w, response.WithMessage(locale.Error(locale.MongoError, r)))
			return
		}
		defer cur.Close(ctx)

		for cur.Next(ctx) {
			//Create a value into which the single document can be decoded
			var elem imageOverviewItem
			err := cur.Decode(&elem)
			if err != nil {
				logging.GetLogger().Error().Err(err).Msg("Couldn't decode document")
				response.InternalError(w, response.WithMessage(locale.Error(locale.MongoError, r)))
				return
			}
			items = append(items, elem)
		}

		docNum, err := coll.CountDocuments(ctx, filter)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("Couldn't count documents")
			response.InternalError(w, response.WithMessage(locale.Error(locale.MongoError, r)))
			return
		}

		response.Ok(w,
			response.WithItems(items),
			response.WithTotalItems(docNum),
			response.WithItemsPerPage(limit),
			response.WithStartIndex(offset))

		// response.Ok(w, &resp{
		// 	Items: items,
		// 	Page:  page,
		// })
		// data := []imageOverviewItem{}
		// for i := 0; i < 8; i++ {
		// 	data = append(data, imageOverviewItem{
		// 		i, fmt.Sprintf("nginx:1.1.%d", i),
		// 		"nginx", fmt.Sprintf("1.1.%d", i), "管理员", "镜像描述",
		// 		rand.Intn(100), rand.Intn(2), time.Now(),
		// 		time.Now(),
		// 		fmt.Sprintf(
		//      "sha256: 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0%d%d00", i, i),
		// 		[]vulnerabilityOverviewItem{
		// 			{0, rand.Intn(10)},
		// 			{1, rand.Intn(8)},
		// 			{2, rand.Intn(15)},
		// 		},
		// 	})
		// }

		// images := assetsImages{
		// 	Images: data,
		// 	Page:   paginationData{8, 10, 1},
		// }
	}
}

// @Summary Images Detail API  Only for docker container
// @Description Get Different Type of Assets in Cluster
// @ID v1-assets-containers
// @Produce json
// @Param node query int false "node id"
// @Router /api/v1/assets/containers [get]
func (api *api) dockerAssets() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var items containerList
		var filter = bson.M{}
		node, err := param.QueryInt(r, "node")
		if err == nil {
			filter = bson.M{"node": node}
		}

		offset, limit := api.getOffsetAndLimit(r)
		opts := options.Find()
		opts.SetSkip(offset)
		opts.SetLimit(limit)
		pickField := bson.M{"detail": 0}
		opts.SetProjection(pickField)

		ctx, cancel := api.getTimeoutCtx(15 * time.Second)
		defer cancel()
		coll := api.mongodb.Collection(containerAssetCol)

		cur, err := coll.Find(ctx, filter, opts)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("Couldn't find document")
			response.InternalError(w, response.WithMessage(locale.Error(locale.MongoError, r)))
			return
		}
		defer cur.Close(ctx)

		for cur.Next(ctx) {
			//Create a value into which the single document can be decoded
			var elem asssetsContainerOverviewItem
			err := cur.Decode(&elem)
			if err != nil {
				logging.GetLogger().Error().Err(err).Msg("Couldn't decode document")
				response.InternalError(w, response.WithMessage(locale.Error(locale.MongoError, r)))
				return
			}
			items = append(items, elem)
		}

		docNum, err := coll.CountDocuments(ctx, filter)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("Couldn't count documents")
			response.InternalError(w, response.WithMessage(locale.Error(locale.MongoError, r)))
			return
		}

		response.Ok(w,
			response.WithItems(items),
			response.WithTotalItems(docNum),
			response.WithItemsPerPage(limit),
			response.WithStartIndex(offset))

		// ID, err := param.QueryInt(r, "node")
		// if err != nil {
		// 	response.InternalError(w, "node id cannot be empty")
		// }

		// items := []asssetsContainerOverviewItem{
		// 	{
		// 		0, "容器1", "容器1-1", "管理员", rand.Intn(10), "nginx:latest", 1,
		// 		ID, rand.Intn(3), time.Now(), time.Now(),
		// 	},
		// 	{
		// 		1, "容器2", "容器1-2", "管理员", rand.Intn(10), "nginx:latest", 1,
		// 		ID, rand.Intn(3), time.Now(), time.Now(),
		// 	},
		// 	{
		// 		2, "容器3", "容器1-3", "管理员", rand.Intn(10), "nginx:latest", 1,
		// 		ID, rand.Intn(3), time.Now(), time.Now(),
		// 	},
		// 	{
		// 		3, "容器4", "容器1-4", "管理员", rand.Intn(10), "nginx:latest", 1,
		// 		ID, rand.Intn(3), time.Now(), time.Now(),
		// 	},
		// 	{
		// 		4, "容器5", "容器1-5", "管理员", rand.Intn(10), "nginx:latest", 1,
		// 		ID, rand.Intn(3), time.Now(), time.Now(),
		// 	},
		// 	{
		// 		5, "容器6", "容器1-6", "管理员", rand.Intn(10), "nginx:latest", 1,
		// 		ID, rand.Intn(3), time.Now(), time.Now(),
		// 	},
		// 	{
		// 		6, "容器7", "容器1-7", "管理员", rand.Intn(10), "nginx:latest", 1,
		// 		ID, rand.Intn(3), time.Now(), time.Now(),
		// 	},
		// }
		// d := assetsContainers{items, paginationData{}}

		// response.Ok(w, d)
	}
}
