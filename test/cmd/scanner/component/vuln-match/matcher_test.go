package vuln_match

import (
	"encoding/json"
	vulnmatch "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/vuln-match"
	"gitlab.com/security-rd/go-pkg/logging"
	"io/ioutil"
	ftypes "scm.tensorsecurity.cn/tensorsecurity-rd/fanal/types"
	"testing"
)

var pkgFile = "fanal_res.json"

func genArtifactFromFile() (ftypes.ArtifactDetail, error) {
	res, err := ioutil.ReadFile(pkgFile)
	if err != nil {
		logging.Get().Err(err).Msg("read fanal res err")
		return ftypes.ArtifactDetail{}, err
	}
	var artifactDetail ftypes.ArtifactDetail
	err = json.Unmarshal(res, &artifactDetail)
	if err != nil {
		logging.Get().Err(err).Msg("unmarshall res err")
		return ftypes.ArtifactDetail{}, err
	}
	return artifactDetail, nil
}

func TestVulnMatch(t *testing.T) {
	matcher, err := vulnmatch.NewMatcher()
	if err != nil {
		t.Fatalf("create new matcher failed:%v", err)
	}

	// update db
	err = vulnmatch.UpdateDB(matcher.Option())
	if err != nil {
		t.Fatalf("update db err:%v", err)
	}

	// generate test pkg info
	artifactDetail, err := genArtifactFromFile()
	if err != nil {
		t.Fatalf("generate artifact err:%v", err)
	}

	err = matcher.MatchVulnerability(artifactDetail)
	if err != nil {
		t.Fatalf("match vuln err:%v", err)
	}

	err = matcher.DumpResult("test_match_res.txt")
	if err != nil {
		t.Fatalf("dump result err:%v", err)
	}

	t.Logf("match vuln end")
}
