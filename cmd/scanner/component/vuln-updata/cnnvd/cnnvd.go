package cnnvd

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/PuerkitoBio/goquery"
	"github.com/boltdb/bolt"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/vuln-updata/register"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
)

type CNNVDUpdata struct {
	db     *bolt.DB
	config cnnvdConfig
}

type cnnvdConfig struct {
	TrivyPath string
}

func init() {
	err := register.Register("cnnvd", openRegistry)
	if err != nil {
		logging.GetLogger().Err(err).Msg("init cnnvd updater err")
	}
}

func openRegistry(registrableComponentConfig register.RegistrableComponentConfig, db *bolt.DB, dbPath string) (register.Registry, error) {
	var cnnvd CNNVDUpdata
	cnnvd.db = db
	cnnvd.config.TrivyPath = filepath.Join(dbPath, "init_trivy.db")
	return &cnnvd, nil
}

func (c *CNNVDUpdata) Updata(wg *sync.WaitGroup) {
	defer wg.Done()
	// fmt.Println("进入函数")
	trivydb, err := bolt.Open(c.config.TrivyPath, 0600, nil)
	if err != nil {
		logging.GetLogger().Error().Err(err)
		return
	}
	defer trivydb.Close()
	WriteToBolt(c.db, trivydb)
}

type CNNVDVulnerabilityInfo struct {
	Number        string `json:"number" bson:"number"`
	RefLink       string `json:"referenceLink" bson:"referenceLink"`
	FixSuggestion string `json:"fix_suggestion"`
	// TODO other fields once we obtain the CNNVD database?
}

func getFromCNNVDdotOrg(ctx context.Context, cveID string) (string, string, string, error) {
	client := http.Client{}

	form := url.Values{}
	form.Add("qcvCnnvdid", cveID) // yes, the form field to find by CVE is called "Cnnvdid", this is not a mistake.
	encodedForm := form.Encode()

	request, err := http.NewRequest("POST", "http://www.cnnvd.org.cn/web/vulnerability/queryLds.tag", strings.NewReader(form.Encode()))
	if err != nil {
		return "", "", "", fmt.Errorf("Failed to prepare request: %w", err)
	}

	request.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Add("Content-Length", strconv.Itoa(len(encodedForm)))

	// This request sometimes takes > 2 minutes (!!!) (usually below a second)
	// Let's do it for as long as we can based on parent ctx
	cnnvdCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	resp, err := client.Do(request.WithContext(cnnvdCtx))
	if err != nil {
		return "", "", "", fmt.Errorf("Failed to send request: %w", err)
	}
	defer resp.Body.Close()
	doc, err := goquery.NewDocumentFromReader(resp.Body)
	// fmt.Println(doc.Html())
	if err != nil {
		return "", "", "", fmt.Errorf("Failed to parse response html doc: %w", err)
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
		return "", "", "", nil // not an error - maybe there isn't such CVE in cnnvd.org's database
	}
	detailsLink := fmt.Sprintf("http://www.cnnvd.org.cn/web/xxk/ldxqById.tag?CNNVD=%s", id)

	request, err = http.NewRequest("GET", detailsLink, nil)
	if err != nil {
		return "", "", "", fmt.Errorf("Failed to prepare request: %w", err)
	}
	resp, err = client.Do(request.WithContext(cnnvdCtx))
	if err != nil {
		return "", "", "", fmt.Errorf("Failed to send request: %w", err)
	}
	doc, err = goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return "", "", "", fmt.Errorf("Failed to parse response html doc: %w", err)
	}
	// fmt.Println(string(doc))
	TmpFixDes := doc.Find(".d_ldjj.m_t_20").First().Find("p").Text()
	// fmt.Println(doc.Html())
	fixDes := strings.TrimSpace(TmpFixDes)
	// fmt.Println(fixDes)
	return id, detailsLink, fixDes, nil
}

// TODO 过滤已有
func WriteToBolt(db *bolt.DB, trivyDb *bolt.DB) {
	ctx := context.Background()

	sum := 0
	var CVEs []string
	err := db.View(func(tx *bolt.Tx) error {
		cnvdBucket := tx.Bucket([]byte("cnvd"))
		if cnvdBucket == nil {
			return fmt.Errorf("CVNND:Not has cnvd bucket")
		}
		cnvdCursor := cnvdBucket.Cursor()
		for k, _ := cnvdCursor.First(); k != nil; k, _ = cnvdCursor.Next() {
			CVEs = append(CVEs, string(k))
		}
		return nil
	})
	if err != nil {
		logging.GetLogger().Error().Err(err)
		return
	}
	err = trivyDb.View(func(tx *bolt.Tx) error {
		trivyBucket := tx.Bucket([]byte("vulnerability"))
		if trivyBucket == nil {
			return fmt.Errorf("CVNND:Not has cnvd bucket")
		}
		trivyCursor := trivyBucket.Cursor()
		for k, _ := trivyCursor.First(); k != nil; k, _ = trivyCursor.Next() {
			if strings.Contains(string(k), "CVE") {
				CVEs = append(CVEs, string(k))
			}
		}
		return nil
	})
	if err != nil {
		logging.GetLogger().Error().Err(err)
		// return
	}
	sum = len(CVEs)
	// fmt.Printf("共有%d\n 漏洞", sum)
	now := 0
	for now = 0; now < sum; {
		err = db.Batch(func(tx *bolt.Tx) error {
			bucket, err := tx.CreateBucketIfNotExists([]byte("cnnvd"))
			if err != nil {
				return fmt.Errorf("CVNND:Can't create cvnnd bucket")
			}
			cnt := 100 // 100条入一次库，避免中断
			for ; cnt > 0 && now < sum; cnt-- {
				//	fmt.Println(now)
				tmpRes := bucket.Get([]byte(CVEs[now]))
				if tmpRes != nil {
					//	log.Infof("Have %s\n", CVEs[now])
					now++
					continue
				}
				//	log.Infof("In query %s\n", CVEs[now])
				id, detailsLink, fixDes, err := getFromCNNVDdotOrg(ctx, string(CVEs[now]))
				if err != nil || id == "" {
					now++
					// fmt.Println(err)
					// fmt.Println("jump")
					continue
				}
				vulnInfo := CNNVDVulnerabilityInfo{}
				vulnInfo.FixSuggestion = fixDes
				vulnInfo.Number = id
				vulnInfo.RefLink = detailsLink
				jsonStr, err := json.Marshal(vulnInfo)
				if err != nil {
					now++
					// fmt.Println("jump")
					continue
				}
				// fmt.Printf("find %s des:%s\n", id, fixDes)
				err = bucket.Put([]byte(CVEs[now]), []byte(jsonStr))

				if err != nil {
					logging.GetLogger().Err(err).Msg("bucket put err")
					continue
				}

				now++
			}
			return nil
		})
		//	logging.GetLogger().Info().Msgf("Cnnvd Update now :%v sum:%v", now, sum)
		if err != nil {
			logging.GetLogger().Err(err).Msg("bold db batch err")
		}
	}
}
