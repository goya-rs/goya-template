package logs

import "fmt"

func ParsePayload(payload []byte) ([]PayloadElem, error) {
	var result []PayloadElem

	for i := 0; i < len(payload); {
		tok, skip, err := readToken(payload, i)
		if err != nil {
			return nil, err
		}

		if skip {
			i++
			continue
		}

		if tok.start+tok.size > len(payload) {
			return nil, fmt.Errorf("out of bounds at %d", i)
		}

		data := payload[tok.start : tok.start+tok.size]

		result = append(result, PayloadElem{
			tok.key: data,
		})

		i = tok.next
	}

	return result, nil
}
