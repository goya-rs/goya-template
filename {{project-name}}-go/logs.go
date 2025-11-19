package main

import (
	"context"
	"errors"
	"fmt"
	"log"

	"os/signal"

	"sync"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
)

func extractPrintableStrings(raw []byte) []string {
	var result []string
	var current []byte

	for _, b := range raw {
		if b >= 0x20 && b <= 0x7E {
			current = append(current, b)
		} else {
			if len(current) > 0 {
				result = append(result, string(current))
				current = nil
			}
		}
	}

	if len(current) > 0 {
		result = append(result, string(current))
	}

	return result
}

func logs(coll *ebpf.Collection, progName string) {
	logMap, ok := coll.Maps["AYA_LOGS"]
	if !ok {
		log.Fatal("AYA_LOGS map not found")
	}

	reader, err := ringbuf.NewReader(logMap)
	if err != nil {
		log.Fatalf("failed to create ringbuf reader: %v", err)
	}
	defer reader.Close()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		defer wg.Done()
		fmt.Println("Listening to Aya logs...")
		fmt.Println("Waiting for Ctrl-C.")

		for {
			select {
			case <-ctx.Done():
				fmt.Println("Log reader stopping...")
				return
			default:
				record, err := reader.Read()
				if err != nil {
					if errors.Is(err, ringbuf.ErrClosed) {
						return
					}
					continue
				}
				msg := extractPrintableStrings(record.RawSample)
				if msg[1] == progName {
					fmt.Printf("[INFO  %s] %s\n", msg[1], msg[len(msg)-1])
				}
			}
		}
	}()

	// Wait for Ctrl-C
	<-ctx.Done()

	fmt.Println("Shutting down...")

	reader.Close()
	wg.Wait()

	fmt.Println("Bye!")
}
