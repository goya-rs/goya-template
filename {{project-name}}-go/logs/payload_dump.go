package logs

import (
	"fmt"
	"strings"
)

func dumpPayloadPretty(elems []PayloadElem) {
	for i, elem := range elems {
		for k, v := range elem {
			switch k {
			case "text":
				fmt.Printf("[%d] TEXT  : %q\n", i, string(v))
			case "ip":
				if len(v) == 4 {
					fmt.Printf("[%d] IP    : %d.%d.%d.%d\n", i, v[0], v[1], v[2], v[3])
				} else {
					fmt.Printf("[%d] IPv6  : %s\n", i, formatIPv6(v))
				}
			case "mac":
				fmt.Printf("[%d] MAC  : %s\n", i, formatMAC(v))
			case "mac_u":
				fmt.Printf("[%d] mac  : %s\n", i, strings.ToUpper(formatMAC(v)))
			default:
				fmt.Printf("[%d] %-5s : %s\n", i, strings.ToUpper(k), hexDump(v))
			}
		}
	}
}

func dumpPayload(elems []PayloadElem) {
	for i, elem := range elems {
		for k, v := range elem {
			fmt.Printf(
				"[%d] %-5s : %s\n",
				i,
				strings.ToUpper(k),
				hexDump(v),
			)
		}
	}
}
