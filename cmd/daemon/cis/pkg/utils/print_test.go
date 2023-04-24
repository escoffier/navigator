package utils

import (
	"encoding/json"
	"io"
	"io/ioutil"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"gitlab.com/tensorsecurity-rd/themis/pkg/check"
)

func parseControlsJsonFile(filepath string) ([]*check.Controls, error) {
	var result []*check.Controls

	d, err := os.ReadFile(filepath)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(d, &result)
	if err != nil {
		return nil, err
	}

	return result, nil
}

func TestPrintSummary(t *testing.T) {
	controlsCollection, err := parseControlsJsonFile("./testdata/controlsCollection.json")
	if err != nil {
		t.Error(err)
	}

	resultTotals := GetSummaryTotals(controlsCollection)
	rescueStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	PrintSummary(resultTotals, "totals")
	w.Close()
	out, _ := ioutil.ReadAll(r)
	os.Stdout = rescueStdout

	assert.Contains(t, string(out), "49 checks PASS\n12 checks FAIL\n14 checks WARN\n0 checks INFO\n\n")
}

func TestPrettyPrintNoSummary(t *testing.T) {
	controlsCollection, err := parseControlsJsonFile("./testdata/controlsCollection.json")
	if err != nil {
		t.Error(err)
	}

	resultTotals := GetSummaryTotals(controlsCollection)
	rescueStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	PrettyPrint(controlsCollection[0], resultTotals, true, false, false, false)
	w.Close()
	out, _ := io.ReadAll(r)
	os.Stdout = rescueStdout

	assert.NotContains(t, string(out), "49 checks PASS")
}

func TestPrettyPrintSummary(t *testing.T) {
	controlsCollection, err := parseControlsJsonFile("./testdata/controlsCollection.json")
	if err != nil {
		t.Error(err)
	}

	resultTotals := GetSummaryTotals(controlsCollection)
	rescueStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	PrettyPrint(controlsCollection[0], resultTotals, false, false, false, false)
	w.Close()
	out, _ := ioutil.ReadAll(r)
	os.Stdout = rescueStdout

	assert.Contains(t, string(out), "49 checks PASS")
}
