package alert

import (
	"bytes"
	"encoding/json"
	"net/http"

	log "github.com/sirupsen/logrus"

	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

func SendInternalAlert(client *http.Client, consoleAddr string, msg string) error {
	internalAlert := model.InternalAlertRequest{
		Msg: msg,
	}
	jsonStr, err := json.Marshal(internalAlert)
	if err != nil {
		log.Errorf("Failed to marshal internal alert %v: %w.", internalAlert, err)
		return err
	}
	req, err := http.NewRequest("POST", consoleAddr, bytes.NewBuffer(jsonStr))
	if err != nil {
		log.Errorf("Failed to prepare request for internal alert %v: %w.", internalAlert, err)
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	_, err = client.Do(req)
	if err != nil {
		log.Errorf("Failed to send internal alert %v: %w.", internalAlert, err)
		return err
	}
	log.Info("Internal alert successfully sent")
	return nil
}

func SendSeccompAlert(client *http.Client, podName string, podUID string, containerID string, profileName string, consoleAddr string, syscall string, phase string, action string) error {
	seccompAlert := model.SeccompProfileAlertRequest{
		PodUID:      podUID,
		Podname:     podName,
		ContainerID: containerID,
		Syscall:     syscall,
		Phase:       phase,
		Action:      action,
		ProfileName: profileName,
	}
	jsonStr, err := json.Marshal(seccompAlert)
	if err != nil {
		log.Errorf("Failed to marshal seccomp alert %v: %w.", seccompAlert, err)
		return err
	}
	req, err := http.NewRequest("POST", consoleAddr, bytes.NewBuffer(jsonStr))
	if err != nil {
		log.Errorf("Failed to prepare request for seccomp alert %v: %w.", seccompAlert, err)
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	_, err = client.Do(req)
	if err != nil {
		log.Errorf("Failed to send seccomp alert %v: %w.", seccompAlert, err)
		return err
	}
	log.Info("Seccomp alert successfully sent")
	return nil
}
