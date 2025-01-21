package pkg

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/pkg/errors"
)

type Alarmer interface {
	Alarm(ctx context.Context, msg string) error
}

type LarkWebhookAlarmer struct {
	httpCli *http.Client
	webhook string
}

type StdOutAlarmer struct {
}

func (cli StdOutAlarmer) Alarm(ctx context.Context, msg string) error {
	fmt.Println(msg)
	return nil
}

func NewLarkWebhookAlarmer(webhook string) *LarkWebhookAlarmer {
	httpCli := http.Client{
		Timeout: 30 * time.Second,
	}
	return &LarkWebhookAlarmer{
		httpCli: &httpCli,
		webhook: webhook,
	}
}

func (cli *LarkWebhookAlarmer) Alarm(ctx context.Context, msg string) error {
	body := LarkWebhookBody{
		MsgType: "text",
	}
	body.Content.Text = msg
	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return errors.Wrap(err, "marshal body failed")
	}
	resp, err := cli.httpCli.Post(cli.webhook, "application/json", bytes.NewReader(bodyBytes))
	if err != nil {
		return errors.Wrap(err, "send msg failed")
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	if resp.StatusCode == http.StatusOK {
		return nil
	}

	if resp.StatusCode != http.StatusOK {
		errStr := fmt.Sprintf("send msg failed, status code: %d", resp.StatusCode)
		if resp.Body != nil {

			bodyBytes, err := io.ReadAll(resp.Body)
			if err != nil {
				return errors.Wrap(err, "read body failed")
			}
			errStr = fmt.Sprintf("%s, body: %s", errStr, string(bodyBytes))
		}
		return errors.New(errStr)
	}
	return nil
}

type LarkWebhookBody struct {
	MsgType string             `json:"msg_type"`
	Content LarkWebhookContent `json:"content"`
}

type LarkWebhookContent struct {
	Text string `json:"text"`
}
