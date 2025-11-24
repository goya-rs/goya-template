package main

import (
	"bytes"
	"fmt"
	"log"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/goya-rs/{{project-name}}/attach"
	"github.com/goya-rs/{{project-name}}/logs"

	_ "embed"
)

const progName = "{{crate_name}}"

{%- case program_type -%}
{%- when "tracepoint" %}
const defaultCategory = "{{tracepoint_category}}"
const defaultName = "{{tracepoint_name}}"
{%- when "xdp", "classifier" %}
const defaultIface = "{{default_iface}}"
{%- when "kprobe", "kretprobe" %}
const defaultFunction = "{{kprobe}}"
{%- when "uprobe", "uretprobe" %}
const defaultBinary = "{{uprobe_target}}"
const defaultFunction = "{{uprobe_fn_name}}"
{%- endcase %}

{%- if program_type == "classifier" %}
const direction = attach.{{direction}}
{% endif %}

{%- if program_type == "uprobe" or program_type == "kprobe" %}
const ret = false
{% endif %}
{%- if program_type == "uretprobe" or program_type == "kretprobe" %}
const ret = true
{% endif %}

//go:embed .ebpf/{{project-name}}
var ebpfBytes []byte

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		panic(err)
	}
	specEbpf, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(ebpfBytes))
	if err != nil {
		log.Fatalf("LoadCollectionSpec failed: %v", err)
	}

	coll, err := ebpf.NewCollection(specEbpf)
	if err != nil {
		log.Fatalf("NewCollection failed: %v", err)
	}
	defer coll.Close()

	prog := coll.Programs[progName]
	if prog == nil {
		log.Fatalf("Program %s not found", progName)
	}

        l, err := link.AttachLSM(link.LSMOptions{
            Program: prog,
        })

	attachment := spec.String()
	if err != nil {
		log.Fatalf("opening {{program_type}}: %s", err)
	}
	defer l.Close()
	fmt.Printf("✅ Program '%s' attached to %s\n", progName, attachment)

	logs.Logs(coll, progName)
}
