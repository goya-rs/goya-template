package main

import (
	"bytes"
	"fmt"
	"log"

{% assign types = "xdp,classifier" %}
{% if types contains program_type %}
	"net"
{% endif %}

	"os"
{% assign types_double = "tracepoint,uprobe,uretprobe" %}
{% if types_double contains program_type %}
	"strings"
{% endif %}

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"

	_ "embed"
)

const progName = "{{crate_name}}"

{%- case program_type -%}
{%- when "tracepoint" %}
const defaultCategory = "{{tracepoint_category}}"
const defaultName = "{{tracepoint_name}}"
const expected = "category:name"
{%- when "xdp", "classifier" %}
const defaultIface = "{{default_iface}}"
{%- when "kprobe", "kretprobe" %}
const defaultFunction = "{{kprobe}}"
{%- when "uprobe", "uretprobe" %}
const defaultBinary = "{{uprobe_target}}"
const defaultFunction = "{{uprobe_fn_name}}"
const expected = "binary:function"
{%- endcase %}

{%- if program_type == "uprobe" or program_type == "kprobe" %}
const ret = false
{% endif %}
{%- if program_type == "uretprobe" or program_type == "kretprobe" %}
const ret = true
{% endif %}

//go:embed .ebpf/{{project-name}}
var ebpfBytes []byte

{%- case program_type -%}
{%- when "uprobe", "uretprobe", "tracepoint" %}
func getAttachment(defaultValue1, defaultValue2 string) (string, string, string, error) {
	value1 := defaultValue1
	value2 := defaultValue2
	attachment := fmt.Sprintf("%s:%s", value1, value2)
	if len(os.Args) > 1 {
		attachment = os.Args[1]
		parts := strings.SplitN(attachment, ":", 2)
		if len(parts) != 2 {
			return "", "", "", fmt.Errorf("invalid attachment format: %s, expected %s", attachment, expected)
		}
		value1, value2 = parts[0], parts[1]
	}
	return value1, value2, attachment, nil
}
{%- endcase %}


{%- case program_type -%}
{%- when "uprobe", "uretprobe" %}
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
	category, name, attachment, err := getAttachment(defaultCategory, defaultName)

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
        {%- when "kprobe", "kretprobe" %}
	attachment := defaultFunction
	if len(os.Args) > 1 {
		attachment = os.Args[1]
	}

	var l link.Link

	if ret {
		l, err = link.Kretprobe(attachment, prog, nil)
	} else {
		l, err = link.Kprobe(attachment, prog, nil)
	}
	if err != nil {
		log.Fatalf("opening k(ret)probe: %s", err)
	}
	{%- when "uprobe", "uretprobe" %}
	l, err := attachUprobe(prog, ret, binary, function)
	if err != nil {
		log.Fatalf("creating u(ret)probe: %s", err)
	}
    {%- endcase %}
	defer l.Close()
	fmt.Printf("✅ Program '%s' attached to %s\n", progName, attachment)

	logs(coll, progName)
}
