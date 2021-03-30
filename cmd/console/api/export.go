package api

import (
	"context"
	"errors"
	"fmt"
	"github.com/360EntSecGroup-Skylar/excelize"
	param "github.com/oceanicdev/chi-param"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/riskexplorer"
	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"net/http"
	"strconv"
	"time"
)

// @Summary Export current assets vulnerability info
// @Description export  current assets  vulnerability in the cluster
// @Produce file type .xlsx
// @Router /api/v1/export [get]
// @Param cluster query string true "k8s cluster"@
func (api *api) export() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var Critical, High, Medium, Low = 0, 0, 0, 0
		var CList, HList, MList, LList []*riskexplorer.ContainerSummary
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*10)
		defer cancel()

		riskFilter := model.GetDefaultVulnerabilityInImagesRiskFilterName()
		sortOrder := "desc"

		offset, limit := api.getOffsetAndLimit(r)
		_, size, err := api.scannerService.GetImageVulnerabilities(
			ctx, riskFilter, offset, limit, sortOrder)
		if err != nil {
			RespAndLog(w, r.Context(),
				NewAnError(http.StatusInternalServerError, err))
			return
		}
		cluster, err := param.QueryString(r, "cluster")
		if err != nil {
			cluster = "default"
		}

		reSvc, ok := riskexplorer.GetRiskExplorerService()
		if !ok {
			RespAndLog(w, ctx, NewAnError(http.StatusServiceUnavailable, errors.New("RiskExplorer Service not found")))
			return
		}

		summary, err := reSvc.WholeSummary(ctx, cluster)
		if err != nil {
			RespAndLog(w, ctx, NewFieldError(http.StatusInternalServerError, err))
			return
		}

		s, _ := api.harborClient.GetScanAllStatus(ctx)

		//Critical High Medium Low Unknown
		//counter

		nameMap := make(map[string]struct{}, 0)
		for _, v := range summary {

			for _, s := range v.ServicesList {
				if s.FinalSeverity == "Critical" {
					Critical++
					CList = append(CList, s.ContainersList...)

				} else if s.FinalSeverity == "High" {
					High++
					HList = append(HList, s.ContainersList...)
				} else if s.FinalSeverity == "Medium" {
					Medium++
					MList = append(MList, s.ContainersList...)
				} else if s.FinalSeverity == "Low" {
					Low++
					LList = append(LList, s.ContainersList...)
				}
				for _, v := range s.ContainersList {
					nameMap[v.Name] = struct{}{}
				}
			}
		}

		categories := map[string]string{"A2": "total", "B1": "On Line Critical", "C1": "On Line High", "D1": "On Line Medium", "E1": "On Line Low", "F1:": "All Image Vulnerability", "G1": "Image Sum", "A21": "severity", "B21": "namespace", "C21": "name"}
		values := map[string]int{"B2": Critical, "C2": High, "D2": Medium, "E2": Low, "F2": int(size), "G2": s.Total}
		f := excelize.NewFile()
		for k, v := range categories {
			f.SetCellValue("Sheet1", k, v)
		}
		for k, v := range values {
			f.SetCellValue("Sheet1", k, v)
		}

		if err := f.AddChart("Sheet1", "A4", `{"type":"col3DClustered","series":[{"name":"Sheet1!$A$1","categories":"Sheet1!$B$1:$E$1","values":"Sheet1!$B$2:$E$2"}],"title":{"name":"Vulnerability details"}}`); err != nil {
			logging.GetLogger().Err(err)
			return
		}

		line := 22

		data := make(map[string]string)
		for _, v := range HList {
			strLine := strconv.Itoa(line)
			data["A"+strLine] = "Critical"
			data["B"+strLine] = v.Namespace
			data["C"+strLine] = v.Name
			line++
		}
		for _, v := range CList {
			strLine := strconv.Itoa(line)
			data["A"+strLine] = "High"
			data["B"+strLine] = v.Namespace
			data["C"+strLine] = v.Name
			line++
		}

		for _, v := range MList {
			strLine := strconv.Itoa(line)
			data["A"+strLine] = "Medium"
			data["B"+strLine] = v.Namespace
			data["C"+strLine] = v.Name
			line++
		}

		for _, v := range LList {
			strLine := strconv.Itoa(line)
			data["A"+strLine] = "Low"
			data["B"+strLine] = v.Namespace
			data["C"+strLine] = v.Name
			line++
		}

		for k, v := range data {
			f.SetCellValue("Sheet1", k, v)
		}
		w.Header().Set("Content-Disposition", "attachment; filename=Vulnerability_details.xlsx")
		w.Header().Set("Content-Type", r.Header.Get("Content-Type"))
		if _, err := f.WriteTo(w); err != nil {
			fmt.Fprintf(w, err.Error())
		}

	}
}
