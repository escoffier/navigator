package cnnvd

import (
	"context"
	"testing"
)

func TestCNNVDQuery(t *testing.T) {
	ctx := context.Background()
	_, _, _, _ = getFromCNNVDdotOrg(ctx, "CVE-2021-26855")
}

func TestCNNVDInsert(t *testing.T) {
	//WriteToBolt()
}
