// Copied into the psiphon-tunnel-core checkout by scripts/stage-psiphon.mjs,
// run there, and removed. It is kept as a real Go file rather than as a string
// inside the script, where its escape sequences did not survive intact.
//
// It borrows tunnel-core's own DecodeServerEntryFields and VerifySignature
// rather than reimplementing Ed25519 over Psiphon's field encoding: the
// question is whether tunnel-core will accept these entries, so tunnel-core is
// what answers it.
//
// Usage: go run . <server-list> <signature-key-file>
package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
)

func main() {
	key, err := os.ReadFile(os.Args[2])
	if err != nil {
		fmt.Println(err)
		os.Exit(2)
	}
	publicKey := strings.TrimSpace(string(key))

	f, err := os.Open(os.Args[1])
	if err != nil {
		fmt.Println(err)
		os.Exit(2)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1<<20), 1<<22)
	total, verified, reported := 0, 0, 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		total++
		fields, err := protocol.DecodeServerEntryFields(line, "", protocol.SERVER_ENTRY_SOURCE_TARGET)
		if err == nil {
			err = fields.VerifySignature(publicKey)
		}
		if err != nil {
			// A handful is enough to see why; a rotated key fails every entry.
			if reported < 3 {
				fmt.Printf("entry %d: %v\n", total, err)
				reported++
			}
			continue
		}
		verified++
	}
	fmt.Printf("%d/%d server entries verify against the signature key\n", verified, total)
	if total == 0 || verified != total {
		os.Exit(1)
	}
}
