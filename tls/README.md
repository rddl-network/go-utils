# tls

The tls package handles common uses cases around TLS certificates.

## Example Usage

```go
package main

import (
        "log"

        "github.com/rddl-network/go-utils/tls"
)

func main() {
        _, err := tls.Get2WayTLSClient("./ca.crt", "./client.crt", "./client.key")
        if err != nil {
                log.Fatalln(err)
        }
}
```
