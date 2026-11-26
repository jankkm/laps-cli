// SPDX-License-Identifier: MIT

package main

import (
	"encoding/json"
	"fmt"
	"io"
)

func writePlain(w, errw io.Writer, results []Result) {
	for _, r := range results {
		if r.Error != "" {
			fmt.Fprintf(errw, "%s: %s\n", r.Computer, r.Error)
		}
		// Always one line per requested computer so output stays aligned with input.
		fmt.Fprintln(w, r.Password)
	}
}

func writeJSON(w io.Writer, results []Result) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(results)
}
