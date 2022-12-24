package saveresult

import (
	"context"
	"errors"
	"fmt"

	"github.com/imroc/req/v3"
	"github.com/segmentio/kafka-go"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	scannermodel "gitlab.com/piccolo_su/vegeta/pkg/model/scanner-model"
	"gitlab.com/security-rd/go-pkg/mq"
)

func SendToConsole(addr string, body []byte) error {
	req.DevMode()
	resp, err := req.R().SetBody(body).Post(addr)
	if err != nil {
		logging.GetLogger().Err(err).Msgf("post scan result error")
		return err
	}
	if resp.StatusCode > 400 {
		logging.GetLogger().Error().Msgf("status code error %d", resp.StatusCode)
		return errors.New(fmt.Sprintf("status code error %d", resp.StatusCode))
	}
	return nil
}

func Send2Kafka(mqWrite mq.Writer, msg []byte) error {
	return mqWrite.Write(
		context.Background(), scannermodel.WebshellKafkaTopic, kafka.Message{
			Topic: scannermodel.WebshellKafkaTopic,
			Key:   []byte("support resource info"),
			Value: msg,
		})
}
