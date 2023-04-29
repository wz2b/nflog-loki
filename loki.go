package main

import (
	"flag"
	"fmt"
	"github.com/grafana/loki-client-go/loki"
	"github.com/grafana/loki-client-go/pkg/urlutil"
	"github.com/prometheus/common/model"
	"log"
	"net/url"
	"time"
)

type LokiMessage struct {
	Labels    model.LabelSet
	Timestamp time.Time
	Message   string
}
type LokiPublisher struct {
	client *loki.Client
	input  chan *LokiMessage
}

func NewLokiPublisher(bufsize int) (*LokiPublisher, error) {
	fmt.Println("creating loki pusher")
	cfg := loki.Config{}

	u, err := url.Parse("https://ha.autofrog.com:3100/loki/api/v1/push")
	if err != nil {
		log.Fatal(err)
	}

	cfg.URL = urlutil.URLValue{URL: u}
	cfg.RegisterFlags(flag.CommandLine)
	connection, err := loki.New(cfg)

	if err != nil {
		return nil, err
	}

	return &LokiPublisher{
		client: connection,
		input:  make(chan *LokiMessage, bufsize),
	}, nil
}

func (l *LokiPublisher) Run() {

	for {
		message := <-l.input
		fmt.Printf("%v  %s\n", message.Labels, message.Message)

		//l.client.Handle(message.Labels, message.Timestamp, message.Message)
	}
}
