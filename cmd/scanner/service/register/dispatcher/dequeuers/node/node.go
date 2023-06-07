package node

import (
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/service/register/dispatcher/dequeuers"
	"gitlab.com/piccolo_su/vegeta/pkg/types/imagesec"
)

type DequeueNodeImageTask struct {
}

func (d *DequeueNodeImageTask) Type() dequeuers.DequeueType {
	return dequeuers.TypeNodeImageTask
}

func (d *DequeueNodeImageTask) Pop() ([]imagesec.ScanSubTask, error) {
	// todo: select tasks from db
	res := make([]imagesec.ScanSubTask, 0)
	//t := imagesec.ScanTask{
	//	ID:         util.GenerateUUIDHex(),
	//	ClusterKey: "f815c6f8-8264-46a0-a273-c039de27492d",
	//	Nodes: []imagesec.NodeInfo{
	//		{
	//			HostName: "cluster02-node02-192.168.3.22-centos",
	//		},
	//	},
	//	SubTasks: []imagesec.ScanSubTask{
	//		{
	//			SubTaskID: "111222",
	//			ImageMeta: imagesec.ImageMeta{
	//				RepoTags: []string{"nginx:latest"},
	//			},
	//		},
	//	},
	//}
	//t := imagesec.ScanTask{
	//	ID:         util.GenerateUUIDHex(),
	//	ClusterKey: "494c5054-4b9b-4944-8452-84b8893c21b7",
	//	Nodes: []imagesec.NodeInfo{
	//		{
	//			HostName: "cluster01-node01-192.168.3.11-centos",
	//		},
	//	},
	//	SubTasks: []imagesec.ScanSubTask{
	//		{
	//			SubTaskID: "111222",
	//			ImageMeta: imagesec.ImageMeta{
	//				RepoTags: []string{"wade23/deploy:deploytest"},
	//			},
	//		},
	//	},
	//}
	t := imagesec.ScanSubTask{
		TaskID:    123456,
		SubTaskID: 66666,
		NodeInfo: imagesec.NodeInfo{
			ClusterKey: "494c5054-4b9b-4944-8452-84b8893c21b7",
			HostName:   "cluster01-node01-192.168.3.11-centos",
		},
		ImageMeta: imagesec.ImageMeta{
			//RepoTags: []string{"wade23/deploy:deploytest"},
			RepoTags: []string{"wade23/webshell-sample:simple"},
		},
	}
	res = append(res, t)

	return res, nil
}

func init() {
	dequeuers.RegisterDequeuer(&DequeueNodeImageTask{})
}
