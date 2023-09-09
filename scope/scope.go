package scope

import (
	"strings"
)

var scopeDescription = map[string]string{
	"openid": "Access user identity and information fields",
}

// FancyScopeList takes a scope string and outputs a slice of scope descriptions
func FancyScopeList(scope string) (arr []string) {
	seen := make(map[string]struct{})
outer:
	for {
		n := strings.IndexAny(scope, ", ")
		var key string
		switch n {
		case 0:
			// first char is matching, no key name found, just continue
			scope = scope[1:]
			continue outer
		case -1:
			// no more matching chars, if scope is empty then we are done
			if len(scope) == 0 {
				return
			}

			// otherwise set the key and empty scope
			key = scope
			scope = ""
		default:
			// set the key and trim from scope
			key = scope[:n]
			scope = scope[n+1:]
		}

		// check if key has been seen already
		if _, ok := seen[key]; ok {
			continue outer
		}

		// set seen flag
		seen[key] = struct{}{}

		// output the description
		if d := scopeDescription[key]; d != "" {
			arr = append(arr, d)
		}
	}
}
