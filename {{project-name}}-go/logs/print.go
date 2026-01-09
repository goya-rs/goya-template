package logs

import "fmt"

func printLogLine(head *Header, msg string) {
	progFile := filenameWithoutExt(head.File)

	if progFile == "main" {
		fmt.Printf("[%s  %s] %s\n", head.Level.String(), head.Target, msg)
		return
	}

	fmt.Printf(
		"[%s  %s::%s] %s\n",
		head.Level.String(),
		head.Target,
		progFile,
		msg,
	)
}
