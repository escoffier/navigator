package ruleMetrics

import (
	"time"

	"github.com/gofrs/uuid"
)

func (rmc RuleMetricsClient) setupTableOnce() error {

	//if rmc.db.Migrator().HasTable(MetricsTableName) {
	//	return nil
	//}
	//
	//log.Infof("Table not present, creating tablename : %s.", MetricsTableName)
	//
	//tableDDL := fmt.Sprintf(`CREATE TABLE %s (
	//	time TIMESTAMP NOT NULL,
	//	ruleId UUID,
	//	hostName VARCHAR(255),
	//	deltaPackets INT,
	//	deltaBytes INT
	//);`, MetricsTableName)
	//
	//result := rmc.db.Exec(tableDDL)
	//if result.Error != nil {
	//	return result.Error
	//}
	//
	//log.Infof("Converting into timescaledb hypertable, tableName : %s.", MetricsTableName)
	//
	//hypertableDDL := fmt.Sprintf("SELECT create_hypertable('%s', 'time');", MetricsTableName)
	//result = rmc.db.Exec(hypertableDDL)
	//if result.Error != nil {
	//	return result.Error
	//}

	return nil
}

func (rmc RuleMetricsClient) insertRulesMetrics(timestamp time.Time, ruleID uuid.UUID, deltaPackets int, deltaBytes int) error {
	// TODO: maybe cache prepared statement https://gorm.io/docs/performance.html#Caches-Prepared-Statement
	//statement := fmt.Sprintf("INSERT INTO %s (time, ruleId, hostName, deltaPackets, deltaBytes) VALUES (?, ?, ?, ?, ?);", MetricsTableName)
	//return rmc.db.Exec(statement, timestamp, ruleID, rmc.hostName, deltaPackets, deltaBytes).Error
	return nil
}
