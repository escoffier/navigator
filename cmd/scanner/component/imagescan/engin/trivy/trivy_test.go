package scanTrivy

import (
	"testing"
)

func TestScanVuln(t *testing.T) {
	// op1 := WithCachePath("/Users/liuqianli/Documents/workfile/vuln/")
	// op3 := WithVulnRootPath("/Users/liuqianli/Documents/workfile/vuln/")
	// op2 := WithPvcPath("/Users/liuqianli/Documents/workfile/")
	//
	// engin, err := NewTrivySrv(op1, op3, op2)
	// if err != nil {
	// 	fmt.Println(err.Error())
	// 	return
	// }
	// vuln, err := engin.Scan(context.Background(), "573320328/liuqianli:v8")
	// if err != nil {
	// 	fmt.Println(err.Error())
	// 	return
	// }
	//
	// for i := range vuln.Results {
	// 	res := vuln.Results[i]
	// 	matchVuln, err := engin.MatchVuln(context.Background(), res.Artifact)
	// 	if err != nil {
	// 		fmt.Println(err.Error())
	// 		return
	// 	}
	// 	for j := range matchVuln {
	// 		fmt.Println(matchVuln[j].Vulnerabilities)
	// 	}
	// }
}
