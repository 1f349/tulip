package types

import "encoding/json"

func encode(data any) string {
	j, err := json.Marshal(data)
	if err != nil {
		panic(err)
	}
	return string(j)
}
