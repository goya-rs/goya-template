package attach

type Direction string

const (
	Ingress Direction = "Ingress"
	Egress  Direction = "Egress"
)

type AttachmentSpec struct {
	Type      string
	Hook1     string
	Hook2     string
	Ret       bool
	Direction Direction
}
