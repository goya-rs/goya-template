package logs

import "fmt"

func readToken(payload []byte, i int) (token, bool, error) {
	if i >= len(payload) {
		return token{}, false, nil
	}

	switch payload[i] {

	case bytePadding:
		// skip padding
		return token{}, true, nil

	case byteText:
		return readTextToken(payload, i)

	case byteMacro:
		return readMacroToken(payload, i)

	default:
		// unknown byte → skip
		return token{}, true, nil
	}
}

func readTextToken(payload []byte, i int) (token, bool, error) {
	if i+textLenOffset >= len(payload) {
		return token{}, false, fmt.Errorf("truncated text at %d", i)
	}

	size := int(payload[i+textLenOffset])
	start := i + textDataOffset

	if start+size > len(payload) {
		return token{}, false, fmt.Errorf("truncated text data at %d", i)
	}

	return token{
		key:   "text",
		start: start,
		size:  size,
		next:  start + size,
	}, false, nil
}

func readMacroToken(payload []byte, i int) (token, bool, error) {
	if i+macroDataOffset > len(payload) {
		return token{}, false, fmt.Errorf("truncated macro at %d", i)
	}

	size := int(payload[i+macroSizeOffset])
	start := i + macroDataOffset

	if start+size > len(payload) {
		return token{}, false, fmt.Errorf("truncated macro data at %d", i)
	}

	key := macroKey(payload[i+macroTypeOffset])

	return token{
		key:   key,
		start: start,
		size:  size,
		next:  start + size,
	}, false, nil
}

func macroKey(t byte) string {
	if k, ok := macroKeys[t]; ok {
		return k
	}
	return "unknown"
}
