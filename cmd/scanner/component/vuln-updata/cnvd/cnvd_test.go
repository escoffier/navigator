//go:build local
// +build local

package cnvd

import (
	"fmt"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/quay/clair/v2/database"
	"github.com/stretchr/testify/assert"
)

func TestCNVDParser(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)
	path := filepath.Join(filepath.Dir(filename))
	dataPath := filepath.Join(path, "/testdata/current_cnvd.tar.gz")
	datastore := database.MockDatastore{}

	var wasCalled bool
	wasCalledCallback := func(metadataKey string, metadata interface{}, severity database.Severity) {
		wasCalled = true
	}

	var returnedKey string
	var returnedMeta interface{}
	var returnedSeverity database.Severity
	appenderCallback := func(metadataKey string, metadata interface{}, severity database.Severity) {
		returnedKey = metadataKey
		returnedMeta = metadata
		returnedSeverity = severity
	}

	a := &cnvdAppender{
		dataPath: dataPath,
	}

	// setup
	err := a.BuildCache(&datastore)
	assert.NoError(t, err)

	// a.WriteToBolt("my.db")
	// // Try getting not existing key

	// given
	wasCalled = false

	// when
	err = a.Append("CVE-Not-exist", wasCalledCallback)

	// then
	assert.NoError(t, err)
	assert.False(t, wasCalled, "If key not present, appender is not called")

	// // Try getting existing key

	// given
	returnedKey = ""
	returnedMeta = nil
	returnedSeverity = database.CriticalSeverity

	// when
	err = a.Append("CVE-2020-7020", appenderCallback)

	// then
	assert.NoError(t, err)
	assert.Equal(t, returnedKey, appenderName)
	assert.NotNil(t, returnedMeta)
	assert.Equal(t, returnedSeverity, database.UnknownSeverity)

	metaArr, ok := returnedMeta.(cnvdMetadataArr)
	assert.True(t, ok)
	assert.Equal(t, (*metaArr)[0].Number, "CNVD-2020-60336")
	assert.Equal(t, (*metaArr)[0].Title, "Elasticsearch信息泄露漏洞（CNVD-2020-60336）")
	assert.Equal(t, (*metaArr)[0].RefLink, "https://staging-website.elastic.co/community/security/")
	assert.Equal(t, (*metaArr)[0].Severity, "中")
	assert.Equal(t, (*metaArr)[0].Description[:19], "Elasticsearch是荷")

	// // Try getting key that has multiple corresponding CNVDs

	// given
	returnedKey = ""
	returnedMeta = nil
	returnedSeverity = database.CriticalSeverity

	// when
	err = a.Append("CVE-2018-20422", appenderCallback)

	// then
	assert.NoError(t, err)
	metaArr, ok = returnedMeta.(cnvdMetadataArr)
	fmt.Printf("%v", metaArr)
	assert.True(t, ok)
	num1 := (*metaArr)[0].Number
	num2 := (*metaArr)[1].Number
	combination1 := num1 == "CNVD-2018-26768" && num2 == "CNVD-2019-00121"
	combination2 := num2 == "CNVD-2019-00121" && num1 == "CNVD-2018-26768"
	assert.True(t, combination1 || combination2, "Both CNVD numbers must appear in output list, no matter the order")

	// // Try getting key after cache purge

	// given
	wasCalled = false
	a.PurgeCache()

	// when
	err = a.Append("CVE-2020-7020", wasCalledCallback)

	// then
	assert.NoError(t, err)
	assert.False(t, wasCalled, "Purging cache should remove key")
}
