package rulemetrics

import (
	"bytes"
	"context"
	"fmt"
	"github.com/pkg/errors"
	"io"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/gofrs/uuid"
	log "github.com/sirupsen/logrus"
)

type iptablesType string

const (
	RuleIDAnnotationKey = "Tensorszec-RuleID"
	MetricsTableName    = "rulesmetrics"
)

const (
	iptablesDumpRulesArgs = "-nxvL"

	iptablesDefault iptablesType = iptablesNft
	iptablesLegacy  iptablesType = "iptables-legacy"
	iptablesNft     iptablesType = "iptables-nft"
)

func (rmc RuleMetricsClient) detectIptablesType() (iptablesType, error) {
	// From iptables 1.8.* we have 2 versions of iptables. We need to determine which one is being used
	// on the host. Similar issue was encountered in kubernetes. See threads below
	// https://github.com/kubernetes-sigs/iptables-wrappers
	// https://github.com/kubernetes/kubernetes/issues/71305
	// https://unix.stackexchange.com/questions/588998/check-whether-iptables-or-nftables-are-in-use
	//
	// Type detection is mostly based on the following script
	// https://github.com/kubernetes-sigs/iptables-wrappers/blob/master/iptables-wrapper-installer.sh
	//
	// Note: we don't use the script itself as it assumes docker base image different than we use, and
	// it's actually quite invasive. I think it's better if our software detects which iptables type to use instead.

	legacyExists, err := rmc.checkIfIptablesTypePresent(iptablesLegacy)
	if err != nil {
		return iptablesDefault, fmt.Errorf("Failed to check if %s is present: %w", iptablesLegacy, err)
	}
	nftExists, err := rmc.checkIfIptablesTypePresent(iptablesNft)
	if err != nil {
		return iptablesDefault, fmt.Errorf("Failed to check if %s is present: %w", iptablesNft, err)
	}

	if legacyExists && !nftExists {
		return iptablesLegacy, nil
	} else if !legacyExists && nftExists {
		return iptablesNft, nil
	} else if !legacyExists && !nftExists {
		return iptablesDefault, fmt.Errorf("Neither %s nor %s is installed", iptablesLegacy, iptablesNft)
	}

	sizeLegacy, err := rmc.countIptablesStdoutSize(iptablesLegacy)
	if err != nil {
		return iptablesDefault, fmt.Errorf("Failed to calculate stdout size of %s", iptablesLegacy)
	}

	sizeNft, err := rmc.countIptablesStdoutSize(iptablesNft)
	if err != nil {
		return iptablesDefault, fmt.Errorf("Failed to calculate stdout size of %s", iptablesNft)
	}

	if sizeLegacy > sizeNft {
		return iptablesLegacy, nil
	} else if sizeNft > sizeLegacy {
		return iptablesNft, nil
	} else { // equal
		return iptablesDefault, fmt.Errorf("Both iptables types returned the same number of bytes, therefore unable to determine which one to use")
	}
}

func (rmc RuleMetricsClient) checkIfIptablesTypePresent(cmd iptablesType) (bool, error) {
	_, err := exec.Command(string(cmd), "--version").Output()
	if err != nil {
		return false, errors.Errorf("Subcommand error, %v", err)
	}
	return true, nil
}

func (rmc RuleMetricsClient) countIptablesStdoutSize(cmd iptablesType) (int, error) {
	versionStdoutBytes, err := exec.Command(string(cmd), "--version").Output()
	if err != nil {
		return 0, fmt.Errorf("Failed to get version of %s: %w", cmd, err)
	}
	versionStdout := string(versionStdoutBytes)

	log.Infof("Detected version, type : %v, version : %v.", string(cmd), versionStdout)
	if strings.Contains(versionStdout, "1.8.0") || strings.Contains(versionStdout, "1.8.1") || strings.Contains(versionStdout, "1.8.2") {
		// According to the script we are based on, 1.8.3 mostly works but can get stuck in an infinite loop if the nft kernel modules are unavailable.
		// Using exec.CommandContext with timeout should fix this problem.
		return 0, fmt.Errorf("iptables 1.8.0 - 1.8.2 have compatibility bugs, upgrade to 1.8.3 or newer")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stdout, err := exec.CommandContext(ctx, string(cmd), iptablesDumpRulesArgs).Output()
	if err != nil {
		return 0, fmt.Errorf("Failed to start subcommand: %w", err)
	}
	return len(stdout), nil
}

func (rmc RuleMetricsClient) grepTensorsecRulesFromIptables() (*bytes.Buffer, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	iptablesCmd := exec.CommandContext(ctx, string(rmc.iptablesCmd), iptablesDumpRulesArgs)
	grepCmd := exec.CommandContext(ctx, "grep", RuleIDAnnotationKey)

	var iptablesStderrBuf bytes.Buffer
	var grepStderrBuf bytes.Buffer

	pipeReader, pipeWriter := io.Pipe()
	iptablesCmd.Stdout = pipeWriter
	iptablesCmd.Stderr = &iptablesStderrBuf

	var grepStdoutBuf bytes.Buffer
	grepCmd.Stdin = pipeReader
	grepCmd.Stdout = &grepStdoutBuf
	grepCmd.Stderr = &grepStderrBuf

	err := iptablesCmd.Start()
	if err != nil {
		return &grepStdoutBuf, fmt.Errorf("Failed to start iptables subcommand (stderr: %s): %w", iptablesStderrBuf.String(), err)
	}
	err = grepCmd.Start()
	if err != nil {
		return &grepStdoutBuf, fmt.Errorf("Failed to start grep subcommand (stderr: %s): %w", grepStderrBuf.String(), err)
	}

	err = iptablesCmd.Wait()
	if err != nil {
		return &grepStdoutBuf, fmt.Errorf("Error encountered when running iptables subcommand (stderr: %s): %w", iptablesStderrBuf.String(), err)
	}

	err = pipeWriter.Close()
	if err != nil {
		return &grepStdoutBuf, fmt.Errorf("Failed to close pipe writer: %w", err)
	}

	err = grepCmd.Wait()
	if exiterr, ok := err.(*exec.ExitError); ok {
		if exiterr.ExitCode() == 1 {
			err = nil // it just means that nothing was matched
		}
	}
	if err != nil {
		return &grepStdoutBuf, fmt.Errorf("Unexpected error encountered when running iptables subcommand (stderr: %s): %w", iptablesStderrBuf.String(), err)
	}

	return &grepStdoutBuf, nil
}

func (rmc RuleMetricsClient) parseIptablesLine(line string) (ruleID uuid.UUID, numPackets int, numBytes int, err error) {
	// Example line:
	//
	// 0        0 LOG        tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            /* cali:SFCYTU4tvtH2GYRY */
	// /* Tensorsec-RuleID=00000000-1f1b-43d1-ad32-d2ee6c1d73c7 */ match-set cali40s:N2jGOMuiLl1e8OuGFI5XtpX src multiport
	// dports 8080 LOG flags 0 level 5 prefix "calico-packet: "

	words := strings.Fields(line)

	numPackets, err = strconv.Atoi(words[0])
	if err != nil {
		return
	}

	numBytes, err = strconv.Atoi(words[1])
	if err != nil {
		return
	}

	for _, word := range words {
		if !strings.Contains(word, RuleIDAnnotationKey) {
			continue
		}
		splitted := strings.Split(word, "=")
		numSplitted := len(splitted)
		if numSplitted != 2 {
			err = fmt.Errorf("Unexpected number of fields (%d) in rule ID word (expected %d) (word is %s)", numSplitted, 2, word)
			return
		}

		uuidWord := splitted[1]
		ruleID, err = uuid.FromString(uuidWord)
		if err != nil {
			err = fmt.Errorf("Invalid rule ID word, expected uuid (%s): %w ", uuidWord, err)
			return
		}
	}
	return
}
