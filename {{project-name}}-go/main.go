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

const crateName = "{{crate_name}}"

{% case program_type %}
  {% when "lsm" %}
const progName = "{{lsm_hook}}"
  {% when "tp_btf" %}
const progName = "{{tracepoint_name}}"
  {% else %}
const progName = crateName
{% endcase %}

{%- case program_type -%}
{%- when "tracepoint" %}
const defaultCategory = "{{tracepoint_category}}"
const defaultName = "{{tracepoint_name}}"
{%- when "tp_btf" %}
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

    {%- case program_type -%}
        {%- when "tracepoint" %}
        spec := attach.AttachmentSpec{
		Type: "{{program_type}}",
		Hook1: defaultCategory,
		Hook2: defaultName,
	}
        spec, err = spec.ResolveAttachment()
	if err != nil {
		log.Fatalf("retrieving attachment: %s", err)
	}
	l, err := spec.AttachTracepoint(prog)
        {%- when "tp_btf" %}
        spec := attach.AttachmentSpec{
		Type: "{{program_type}}",
		Hook1: defaultName,
	}
        spec, err = spec.ResolveAttachment()
	if err != nil {
		log.Fatalf("retrieving attachment: %s", err)
	}
	l, err := spec.AttachBTFTracepoint(prog)
        {%- when "xdp" %}
        spec := attach.AttachmentSpec{
		Type: "{{program_type}}",
		Hook1: defaultIface,
	}
        spec, err = spec.ResolveAttachment()
	if err != nil {
		log.Fatalf("retrieving attachment: %s", err)
	}
	l, err := spec.AttachXDP(prog)
        {%- when "classifier" %}
        spec := attach.AttachmentSpec{
		Type: "{{program_type}}",
		Hook1: defaultIface,
		Direction: direction,
	}
        spec, err = spec.ResolveAttachment()
	if err != nil {
		log.Fatalf("retrieving attachment: %s", err)
	}
	l, err := spec.AttachTC(prog)
        {%- when "kprobe", "kretprobe" %}
        spec := attach.AttachmentSpec{
		Type: "{{program_type}}",
		Hook1: defaultFunction,
		Ret: ret,
	}
        spec, err = spec.ResolveAttachment()
	if err != nil {
		log.Fatalf("retrieving attachment: %s", err)
	}
	l, err := spec.AttachKprobe(prog)
	{%- when "uprobe", "uretprobe" %}
        spec := attach.AttachmentSpec{
		Type: "{{program_type}}",
		Hook1: defaultBinary,
		Hook2: defaultFunction,
		Ret: ret,
	}
        spec, err = spec.ResolveAttachment()
	if err != nil {
		log.Fatalf("retrieving attachment: %s", err)
	}
	l, err := spec.AttachUprobe(prog)
	{%- when "lsm" %}
        spec := attach.AttachmentSpec{
		Type: "{{program_type}}",
		Hook1: "{{lsm_hook}}",
	}
        spec, err = spec.ResolveAttachment()
	if err != nil {
		log.Fatalf("retrieving attachment: %s", err)
	}
	l, err := spec.AttachLSM(prog)
    {%- endcase %}
	attachment := spec.String()
	if err != nil {
		log.Fatalf("opening {{program_type}}: %s", err)
	}
	defer l.Close()
	fmt.Printf("✅ Program '%s' attached to %s\n", crateName, attachment)

	logs.Logs(coll, crateName)
}
