package output

import (
	"os"

	"github.com/olekukonko/tablewriter"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner-cicd/pkg/structures"
)

func Terminal(resultInfo structures.ResultInfo) error {
	outputTable(resultInfo.Data.Item.RejectMsg)
	outputTable(resultInfo.Data.Item.Vulu)
	outputTable(resultInfo.Data.Item.Sensitive)
	outputTable(resultInfo.Data.Item.Virus)
	outputTable(resultInfo.Data.Item.Webshell)
	outputTable(resultInfo.Data.Item.Envs)

	return nil
}

func outputTable(data [][]string) {
	table := tablewriter.NewWriter(os.Stdout)
	if len(data) != 0 {
		table.SetHeader(data[0])
		for k := range data {
			if k == 0 {
				continue
			}
			table.Append(data[k])
		}
		table.Render()
	}
}
