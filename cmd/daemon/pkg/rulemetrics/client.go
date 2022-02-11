package rulemetrics

import (
	"fmt"
	"strings"
	"time"

	"github.com/gofrs/uuid"
	log "github.com/sirupsen/logrus"
)

type Client struct {
	iptablesCmd iptablesType

	lastNumBytesMap   map[uuid.UUID]int
	lastNumPacketsMap map[uuid.UUID]int
	hostName          string
}

func NewClient(hostName string) (*Client, error) {
	rmc := Client{
		hostName:          hostName,
		lastNumBytesMap:   make(map[uuid.UUID]int),
		lastNumPacketsMap: make(map[uuid.UUID]int),
	}

	itype, err := rmc.detectIptablesType()
	if err != nil {
		return nil, fmt.Errorf("Failed to detect iptables type: %w", err)
	}
	rmc.iptablesCmd = itype
	log.Infof("Detected iptables type : %v.", string(rmc.iptablesCmd))

	err = rmc.setupTableOnce()
	if err != nil {
		return nil, fmt.Errorf("Failed to setup tables for rule metrics: %w", err)
	}

	return &rmc, nil
}

func (rmc Client) doSample() error {
	timestamp := time.Now()

	grepped, err := rmc.grepTensorsecRulesFromIptables()
	if err != nil {
		return fmt.Errorf("Failed to get output from iptables: %w", err)
	}

	totalInserted := 0
	for _, line := range strings.Split(grepped.String(), "\n") {
		if len(line) == 0 {
			continue
		}

		ruleID, numPackets, numBytes, err := rmc.parseIptablesLine(line)
		if err != nil {
			return fmt.Errorf("Failed to parse iptables line: %w", err)
		}

		if _, ok := rmc.lastNumPacketsMap[ruleID]; !ok {
			rmc.lastNumPacketsMap[ruleID] = 0
		}
		if _, ok := rmc.lastNumBytesMap[ruleID]; !ok {
			rmc.lastNumBytesMap[ruleID] = 0
		}

		// Handle external clearing of iptables counters
		if rmc.lastNumPacketsMap[ruleID] > numPackets {
			rmc.lastNumPacketsMap[ruleID] = 0
		}
		if rmc.lastNumBytesMap[ruleID] > numBytes {
			rmc.lastNumBytesMap[ruleID] = 0
		}

		deltaPackets := numPackets - rmc.lastNumPacketsMap[ruleID]
		deltaBytes := numBytes - rmc.lastNumBytesMap[ruleID]

		rmc.lastNumPacketsMap[ruleID] = numPackets
		rmc.lastNumBytesMap[ruleID] = numBytes

		// TODO batch insert
		err = rmc.insertRulesMetrics(timestamp, ruleID, deltaPackets, deltaBytes)
		if err != nil {
			return fmt.Errorf("Failed to insert metrics into db: %w", err)
		}
		totalInserted++
	}

	log.Infof("Rule metrics sampled, inserted : %v.", totalInserted)

	return nil
}

func (rmc Client) Start() {
	go func() {
		for {
			err := rmc.doSample()
			if err != nil {
				log.Errorf("rule metrics do sample error, %v.", err)
			}
			time.Sleep(time.Second * 10)
		}
	}()
}
