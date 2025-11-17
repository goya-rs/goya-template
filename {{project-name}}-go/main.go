package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"

{% assign types = "xdp,classifier" %}
{% if types contains program_type %}
	"net"
{% endif %}

	"os"
	"os/signal"
{% assign types_double = "tracepoint,uprobe,uretprobe" %}
{% if types_double contains program_type %}
	"strings"
{% endif %}
	"syscall"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	_ "embed"
)

const progName = "{{crate_name}}"

{%- case program_type -%}
{%- when "tracepoint" %}
const defaultCategory = "{{tracepoint_category}}"
const defaultName = "{{tracepoint_name}}"
{%- when "xdp", "classifier" %}
const defaultIface = "{{default_iface}}"
{%- when "kprobe" %}
const defaultFunction = "{{kprobe}}"
{%- when "uprobe", "uretprobe" %}
const defaultBinary = "{{uprobe_target}}"
const defaultFunction = "{{uprobe_fn_name}}"
{%- endcase %}

//go:embed .ebpf/{{project-name}}
var ebpfBytes []byte

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

{%- case program_type -%}
{%- when "uprobe", "uretprobe" %}
func getAttachment(defaultBinary, defaultFunction string) (string, string, string, error) {
	binary := defaultBinary
	function := defaultFunction
	attachment := fmt.Sprintf("%s:%s", binary, function)
	if len(os.Args) > 1 {
		attachment = os.Args[1]
		parts := strings.SplitN(attachment, ":", 2)
		if len(parts) != 2 {
			return "", "", "", fmt.Errorf("invalid attachment format: %s, expected binary:function", attachment)
		}
		binary, function = parts[0], parts[1]
	}
	return binary, function, attachment, nil
}


func attachUprobe(prog *ebpf.Program, isReturn bool, binary, function string) (link.Link, error) {
	// Open binary
	ex, err := link.OpenExecutable(binary)
	if err != nil {
		return nil, fmt.Errorf("opening executable: %w", err)
	}

	// Attach according to type
	if isReturn {
		return ex.Uretprobe(function, prog, nil)
	}
	return ex.Uprobe(function, prog, nil)
}
{%- endcase %}

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		panic(err)
	}
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(ebpfBytes))
	if err != nil {
		log.Fatalf("LoadCollectionSpec failed: %v", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("NewCollection failed: %v", err)
	}
	defer coll.Close()

	prog := coll.Programs[progName]
	if prog == nil {
		log.Fatalf("Program %s not found", progName)
	}

    {%- case program_type -%}
	{%- when "uprobe", "uretprobe" %}
	binary, function, attachment, err := getAttachment(defaultBinary, defaultFunction)
	if err != nil {
		log.Fatalf("creating attachment: %s", err)
	}
    {%- endcase %}

    {%- case program_type -%}
        {%- when "tracepoint" %}
        category := defaultCategory
        name := defaultName
	attachment := fmt.Sprintf("%s:%s", category, name)

        if len(os.Args) > 1 {
            attachment = os.Args[1]
            parts := strings.SplitN(attachment, ":", 2)
            if len(parts) != 2 {
                log.Fatalf("invalid attachment format: %s, expected category:name", attachment)
            }
            category, name = parts[0], parts[1]
        }

	l, err := link.Tracepoint(category, name, prog, nil)
	if err != nil {
		log.Fatalf("opening tracepoint: %s", err)
	}
        {%- when "xdp" %}
	attachment := defaultIface
	if len(os.Args) > 1 {
		attachment = os.Args[1]
	}
	iface, err := net.InterfaceByName(attachment)
	if err != nil {
		log.Fatalf("Interface not found: %v", err)
	}
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   prog,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatalf("AttachXDP failed: %v", err)
	}
        {%- when "classifier" %}
	attachment := defaultIface
	if len(os.Args) > 1 {
		attachment = os.Args[1]
	}
	iface, err := net.InterfaceByName(attachment)
	if err != nil {
		log.Fatalf("Interface not found: %v", err)
	}
	l, err := link.AttachTCX(link.TCXOptions{
		Interface: iface.Index,
		Program:   prog,
		Attach:    ebpf.AttachTCX{{direction}},
	})
	if err != nil {
		log.Fatalf("AttachTCX failed: %v", err)
	}
        {%- when "kprobe" %}
	attachment := defaultFunction
	if len(os.Args) > 1 {
		attachment = os.Args[1]
	}

	l, err := link.Kprobe(attachment, prog, nil)
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	{%- when "uretprobe" %}
	l, err := attachUprobe(prog, true, binary, function)
	if err != nil {
		log.Fatalf("creating uretprobe: %s", err)
	}
	{%- when "uprobe" %}
	l, err := attachUprobe(prog, false, binary, function)
	if err != nil {
		log.Fatalf("creating uprobe: %s", err)
	}
    {%- endcase %}
	defer l.Close()
	fmt.Printf("✅ Program '%s' attached to %s\n", progName, attachment)

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
		    fmt.Printf("[INFO  %s] %s\n", msg[1], msg[len(msg)-1])
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
