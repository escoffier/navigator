package scap

import "gitlab.com/piccolo_su/vegeta/cmd/console/models"

type CronJob struct {
	Job    `json:",inline"`
	Status bool  `json:"status"`
	Cron   *Cron `json:"cron"`
}

type Cron struct {
	// 类型，1:-, 2:每天，3:每周，4:每月，5.每年
	Type uint8 `json:"type"`
	// 时间间隔
	// 当type为1时，忽略
	// 当type为2时，格式为 时:分:秒
	// 当type为3时，格式为 week/时:分:秒
	// 当type为4时，格式为 day/时:分:秒
	// 当type为5时，格式为 month/day/时:分:秒
	Time string `json:"time"`
}

type CronJobDetail struct {
	ID     uint  `json:"id"`
	Cron   *Cron `json:"cron"`
	Status bool  `json:"status"`
	// 策略id, 0为默认策略
	PolicyID     uint                `json:"policyId"`
	PolicyName   string              `json:"policyName"`
	ClusterInfos []ClusterInfoDetail `json:"clusterInfo"`
}

type CronJobResp struct {
	models.ID `json:",inline"`
}
