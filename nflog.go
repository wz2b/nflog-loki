package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	nflog "github.com/florianl/go-nflog/v2"
)

type groupArray []uint16

var groups groupArray

func (i *groupArray) String() string {
	groupStrings := make([]string, len(*i))

	for n, v := range *i {
		groupStrings[n] = string(v)
	}

	return strings.Join(groupStrings, ",")
}

func (i *groupArray) Set(value string) error {
	v, _ := strconv.ParseUint(value, 10, 16)
	*i = append(*i, uint16(v))
	return nil
}

func main() {
	flag.Var(&groups, "g", "Some description for this param.")

	flag.Parse()

	if len(groups) == 0 {
		groups = groupArray{2}
	}

	fmt.Printf("groups: %v\n", groups)

	config := nflog.Config{
		Group:    2,
		Copymode: nflog.CopyPacket,
		Bufsize:  128,
		Flags:    nflog.FlagConntrack,
	}

	nf, err := nflog.Open(&config)

	if err != nil {
		fmt.Println("could not open nflog socket:", err)
		return
	}
	defer nf.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	pusher, err := NewLokiPublisher(1000)
	if err != nil {
		log.Fatalln("Unable to create loki pusher", err)
	}
	go pusher.Run()

	processor := NewPcap(1000, pusher)

	// hook that is called for every received packet by the nflog group
	hook := func(attrs nflog.Attribute) int {
		processor.input <- &attrs
		return 0
	}

	go processor.Run()

	fmt.Println("Creating error function")
	// errFunc that is called for every error on the registered hook
	errFunc := func(e error) int {
		// Just log the error and return 0 to continue receiving packets
		fmt.Fprintf(os.Stderr, "received error on hook: %v", e)
		return 0
	}

	fmt.Println("registering hook and error handlers")
	// Register your function to listen on nflog group 100
	err = nf.RegisterWithErrorFunc(ctx, hook, errFunc)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to register hook function: %v", err)
		return
	}

	// Block till the context expires
	<-ctx.Done()
	fmt.Println("Timeout")

}
