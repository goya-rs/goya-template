package logs

type PayloadElem map[string][]byte

type token struct {
	key   string
	start int
	size  int
	next  int
}

const (
	bytePadding = 0x00
	byteMacro   = 0x01
	byteText    = 0x14

	textLenOffset   = 1
	textDataOffset  = 3
	macroTypeOffset = 2
	macroSizeOffset = 4
	macroDataOffset = 6
)

var macroKeys = map[byte]string{
	0x01: "default",
	0x02: "hex",
	0x03: "hex_u",
	0x04: "ip",
	0x05: "mac",
	0x06: "mac_u",
	0x07: "ptr",
}
