package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	nflog "github.com/florianl/go-nflog/v2"
)

func main() {
	//var count uint64 = 0

	//pusher, err := NewLokiPublisher()
	//if err != nil {
	//	panic(err)
	//}

	config := nflog.Config{
		Group:    2,
		Copymode: nflog.CopyPacket,
		Bufsize:  128,
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
