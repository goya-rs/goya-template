package logs

import (
	"context"
	"fmt"
	"log"
	"os/signal"
	"sync"
	"syscall"

	"github.com/cilium/ebpf"
)

func Logs(coll *ebpf.Collection, progName string) {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		defer wg.Done()
		fmt.Println("Listening to Aya logs...")
		fmt.Println("Waiting for Ctrl-C.")

		err := runReader(ctx, coll, func(raw []byte) {
			header, payload, err := splitHeaderPayload(raw)
			if err != nil {
				log.Println(err)
				return
			}

			elems, err := ParsePayload(payload)
			if err != nil {
				log.Println(err)
				return
			}

			head, err := ParseHeader(header)
			if err != nil {
				log.Println(err)
				return
			}

			if head.Target != progName {
				return
			}

			msg := FormatPayload(elems)
			printLogLine(head, msg)
		})

		if err != nil {
			log.Println(err)
		}
	}()

	<-ctx.Done()
	fmt.Println("Shutting down...")
	wg.Wait()
	fmt.Println("Bye!")
}
