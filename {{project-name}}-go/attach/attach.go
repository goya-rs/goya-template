package attach

import (
	"fmt"

	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

func (spec AttachmentSpec) AttachUprobe(prog *ebpf.Program) (link.Link, error) {
	ex, err := link.OpenExecutable(spec.Hook1)
	if err != nil {
		return nil, fmt.Errorf("opening executable: %w", err)
	}

	var l link.Link

	if spec.Ret {
		l, err = ex.Uretprobe(spec.Hook2, prog, nil)
	} else {
		l, err = ex.Uprobe(spec.Hook2, prog, nil)
	}
	return l, err
}

func (spec AttachmentSpec) AttachTracepoint(prog *ebpf.Program) (link.Link, error) {
	return link.Tracepoint(spec.Hook1, spec.Hook2, prog, nil)
}

func (spec AttachmentSpec) AttachBTFTracepoint(prog *ebpf.Program) (link.Link, error) {
	return link.AttachTracing(link.TracingOptions{
		Program: prog,
	})
}

func (spec AttachmentSpec) AttachLSM(prog *ebpf.Program) (link.Link, error) {
	return link.AttachLSM(link.LSMOptions{Program: prog})
}

func (spec AttachmentSpec) AttachKprobe(prog *ebpf.Program) (link.Link, error) {
	if spec.Ret {
		return link.Kretprobe(spec.Hook1, prog, nil)
	} else {
		return link.Kprobe(spec.Hook1, prog, nil)
	}
}

func (spec AttachmentSpec) AttachXDP(prog *ebpf.Program) (link.Link, error) {
	iface, err := net.InterfaceByName(spec.Hook1)
	if err != nil {
		return nil, fmt.Errorf("Interface not found: %v", err)
	}
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   prog,
		Interface: iface.Index,
	})
	return l, err
}

func (spec AttachmentSpec) AttachTC(prog *ebpf.Program) (link.Link, error) {
	iface, err := net.InterfaceByName(spec.Hook1)
	if err != nil {
		return nil, fmt.Errorf("Interface not found: %v", err)
	}

	attach := ebpf.AttachTCXEgress

	if spec.Direction == Ingress {
		attach = ebpf.AttachTCXIngress
	}

	l, err := link.AttachTCX(link.TCXOptions{
		Interface: iface.Index,
		Program:   prog,
		Attach:    attach,
	})
	return l, err
}
