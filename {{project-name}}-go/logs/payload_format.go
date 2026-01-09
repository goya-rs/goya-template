package logs

import (
	"encoding/binary"
	"fmt"
	"strings"
)

func FormatPayload(elems []PayloadElem) string {
	var b strings.Builder

	for _, elem := range elems {
		for k, v := range elem {
			switch k {
			case "text":
				b.WriteString(string(v))
			case "ip":
				if len(v) == 4 {
					fmt.Fprintf(&b, "%d.%d.%d.%d", v[0], v[1], v[2], v[3])
				} else {
					b.WriteString(formatIPv6(v))
				}
			case "mac":
				b.WriteString(formatMAC(v))
			case "mac_u":
				b.WriteString(strings.ToUpper(formatMAC(v)))
			case "hex":
				fmt.Fprintf(&b, "%x", binary.LittleEndian.Uint32(v))
			case "hex_u":
				fmt.Fprintf(&b, "%X", binary.LittleEndian.Uint32(v))
			case "ptr":
				fmt.Fprintf(&b, "%#x", binary.LittleEndian.Uint32(v))
			case "default":
				fmt.Fprintf(&b, "%d", binary.LittleEndian.Uint32(v))
			default:
				b.WriteString(hexDump(v))
			}
		}
	}
	return b.String()
}
