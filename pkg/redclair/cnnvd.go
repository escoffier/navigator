package redclair

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/rs/zerolog"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

const (
	cve2cnnvdCollection = "CVE2CNNVD"

	cve2cnnvdStaleEntryTime = time.Hour * 24 * 7
)

type cve2cnnvdMapping struct {
	ID        primitive.ObjectID `json:"db_id,omitempty" bson:"_id,omitempty"`
	CVE       string             `json:"cve" bson:"cve"`
	CVNND     string             `json:"cvnnd" bson:"cvnnd"`
	CVNNDLink string             `json:"cvnndLink" bson:"cvnndLink"`
	UpdatedAt int64              `json:"updatedAt" bson:"updatedAt"`
}

func (r *Redclair) enrichWithCNNVD(ctx context.Context, vulns []VulnerabilityInfo) error {
	// TODO: Inefficient use of lock, can be improved. Maybe we can use upsert instead of mutex altogether.
	r.cve2cnnvdCollectionMux.Lock()
	defer r.cve2cnnvdCollectionMux.Unlock()

	for i := range vulns {
		select {
		case <-ctx.Done():
			return fmt.Errorf("Took too long: %w", ctx.Err())
		default:
		}

		cve := vulns[i].ID
		if !strings.Contains(cve, "CVE") {
			continue
		}

		var cve2cnnvd cve2cnnvdMapping

		filter := bson.M{"cve": cve}
		queryResult := r.mongodb.Collection(cve2cnnvdCollection).FindOne(ctx, filter)
		if queryResult.Err() != nil && queryResult.Err() != mongo.ErrNoDocuments {
			return fmt.Errorf("Unexpected error when getting collection: %w", queryResult.Err())
		}

		if queryResult.Err() == mongo.ErrNoDocuments {
			zerolog.Ctx(ctx).Info().Str("cve", cve).Msg("CVE to CNNVD mapping not found in database, will get from cnnvd.org")

			r.cve2cnnvdCollectionMux.Unlock()
			cnnvd, link, err := r.getFromCNNVDdotOrg(ctx, cve)
			r.cve2cnnvdCollectionMux.Lock()
			if err != nil {
				return fmt.Errorf("Failed to get CNNVD from cnnvd.org: %w", err)
			}

			newMapping := cve2cnnvdMapping{
				ID:        primitive.NewObjectIDFromTimestamp(time.Now()),
				CVE:       cve,
				CVNND:     cnnvd,
				CVNNDLink: link,
				UpdatedAt: time.Now().Unix(),
			}

			_, err = r.mongodb.Collection(cve2cnnvdCollection).InsertOne(ctx, newMapping)
			if err != nil {
				return fmt.Errorf("Failed to insert new CVE to CNNVD mapping to mongo: %w", err)
			}

			vulns[i].CNNVDs = append(vulns[i].CNNVDs, CNNVDVulnerabilityInfo{
				Number:  cnnvd,
				RefLink: link,
			})
			continue
		}

		err := queryResult.Decode(&cve2cnnvd)
		if err != nil {
			return fmt.Errorf("Failed to decode query result: %w", err)
		}

		staleEntryTime := (time.Now().Add(-1 * cve2cnnvdStaleEntryTime)).Unix()
		if cve2cnnvd.UpdatedAt < staleEntryTime {
			zerolog.Ctx(ctx).Info().Str("cve", cve).Msg("CVE to CNNVD mapping is stale, will get from cnnvd.org")

			r.cve2cnnvdCollectionMux.Unlock()
			cnnvd, link, err := r.getFromCNNVDdotOrg(ctx, cve)
			r.cve2cnnvdCollectionMux.Lock()
			if err != nil {
				return fmt.Errorf("Failed to get CNNVD from cnnvd.org: %w", err)
			}

			// TODO: if new cnnvd or link is different, then we should also invalide layer cache for all layers,
			// which had this vulnerability.

			newMapping := cve2cnnvdMapping{
				ID:        cve2cnnvd.ID,
				CVE:       cve,
				CVNND:     cnnvd,
				CVNNDLink: link,
				UpdatedAt: time.Now().Unix(),
			}

			filter := bson.M{"_id": cve2cnnvd.ID}
			update := bson.M{"$set": newMapping}

			_, err = r.mongodb.Collection(cve2cnnvdCollection).UpdateOne(ctx, filter, update)
			if err != nil {
				return fmt.Errorf("Failed to update CVE to CNNVD mapping in mongo: %w", err)
			}

			vulns[i].CNNVDs = append(vulns[i].CNNVDs, CNNVDVulnerabilityInfo{
				Number:  cnnvd,
				RefLink: link,
			})
			continue
		}

		vulns[i].CNNVDs = append(vulns[i].CNNVDs, CNNVDVulnerabilityInfo{
			Number:  cve2cnnvd.CVNND,
			RefLink: cve2cnnvd.CVNNDLink,
		})

	}

	return nil
}

func (r *Redclair) getFromCNNVDdotOrg(ctx context.Context, cveID string) (string, string, error) {
	client := http.Client{}

	form := url.Values{}
	form.Add("qcvCnnvdid", cveID) // yes, the form field to find by CVE is called "Cnnvdid", this is not a mistake.
	encodedForm := form.Encode()

	request, err := http.NewRequest("POST", "http://www.cnnvd.org.cn/web/vulnerability/queryLds.tag", strings.NewReader(form.Encode()))
	if err != nil {
		return "", "", fmt.Errorf("Failed to prepare request: %w", err)
	}

	request.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Add("Content-Length", strconv.Itoa(len(encodedForm)))

	// This request sometimes takes > 2 minutes (!!!) (usually below a second)
	// Let's do it for as long as we can based on parent ctx
	cnnvdCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	resp, err := client.Do(request.WithContext(cnnvdCtx))
	if err != nil {
		return "", "", fmt.Errorf("Failed to send request: %w", err)
	}
	defer resp.Body.Close()

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return "", "", fmt.Errorf("Failed to parse response html doc: %w", err)
	}

	// Example case:
	// ...
	// <div class="fl" id="vulner_0">
	//   <p>
	//    <a href="/web/xxk/ldxqById.tag?CNNVD=CNNVD-201604-564" target="_blank">CNNVD-201604-564</a>
	//    <span>&nbsp;&nbsp;&nbsp;&nbsp;厂商&nbsp;&nbsp;</span>
	//    <a href="/web/vulnerability/querylist.tag?cpvendor=jq_project"> jq_project... </a>
	//   </p>
	// </div>
	// ...
	id := doc.Find("#vulner_0").First().Find("p").Find("a").First().Text()
	if id == "" {
		return "", "", nil // not an error - maybe there isn't such CVE in cnnvd.org's database
	}
	detailsLink := fmt.Sprintf("http://www.cnnvd.org.cn/web/xxk/ldxqById.tag?CNNVD=%s", id)

	return id, detailsLink, nil
}
