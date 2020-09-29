#!/bin/bash

cat <<EOF > tohex.go
package main

import (
        "encoding/hex"
        "io/ioutil"
        "os"
        "fmt"
)

func main() {
        buf, err := ioutil.ReadFile("icmp.elf")
        if err != nil {
                os.Exit(1)
        }
        body := fmt.Sprintf(\`package udponicmp

// ELFBytes ELFBytes
const ELFBytes = "%s"\`,hex.EncodeToString(buf))

        if err = ioutil.WriteFile("../elf.go", []byte(body), 0644); err != nil {
                os.Exit(1)
        }
}
EOF

go run tohex.go
exitcode=$?
rm -f tohex.go
exit $exitcode