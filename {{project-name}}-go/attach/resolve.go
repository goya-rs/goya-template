package attach

import (
	"fmt"

	"os"
	"strings"
)

func (spec AttachmentSpec) ResolveAttachment() (AttachmentSpec, error) {
	if len(os.Args) > 1 {
		parts := strings.SplitN(os.Args[1], ":", 2)
		if len(parts) != 2 && spec.Hook2 != "" {
			return AttachmentSpec{}, fmt.Errorf("invalid attachment format: %s", os.Args[1])
		}
		spec.Hook1 = parts[0]
		if len(parts) > 1 {
			spec.Hook2 = parts[1]
		}
	}

	return spec, nil
}

func (spec AttachmentSpec) String() string {
	if spec.Hook2 != "" {
		return fmt.Sprintf("%s:%s", spec.Hook1, spec.Hook2)
	}
	return spec.Hook1
}
