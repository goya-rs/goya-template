package logs

import "fmt"

func dumpHeader(h *Header) {
	fmt.Println("HEADER")
	fmt.Printf("  Target   : %s\n", h.Target)
	fmt.Printf("  Level    : %s\n", h.Level.String())
	fmt.Printf("  Module   : %s\n", h.Module)
	fmt.Printf("  File     : %s\n", h.File)
	fmt.Printf("  Line     : %d\n", h.Line)
	fmt.Printf("  NumArgs  : %d\n", h.NumArgs)
}
