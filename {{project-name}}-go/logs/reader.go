package logs

import (
	"context"
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
)

func runReader(
	ctx context.Context,
	coll *ebpf.Collection,
	handle func(raw []byte),
) error {
	logMap, ok := coll.Maps["AYA_LOGS"]
	if !ok {
		return fmt.Errorf("AYA_LOGS map not found")
	}

	reader, err := ringbuf.NewReader(logMap)
	if err != nil {
		return err
	}
	defer reader.Close()

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
			record, err := reader.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					return nil
				}
				continue
			}
			if len(record.RawSample) > 0 {
				handle(record.RawSample)
			}
		}
	}
}
