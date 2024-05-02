# logger
The logger package serve a centralized module for structured logging.

## Log levels
The following log levels are supported sorted from most to least logging `debug`, `info`, `warn`, `error`.

## Usage
This package uses key-value pairs to create logs. Any logging with an uneven amount of `keyvals` will result in an error. You can pass any number of key-value pairs to adjust these logs to your liking.

```go
package main

import (
    log "github.com/rddl-network/go-utils/logger"
)

func main() {
    logger := log.GetLogger(log.DEBUG)

    logger.Debug("key", "val")
    logger.Info("key", "val")
    logger.Warn("key", "val")
    logger.Error("key", "val")
}
```

Output:
```
ts=2024-04-16T08:41:25.002433743Z caller=level.go:71 level=debug key=val
ts=2024-04-16T08:41:25.002487452Z caller=level.go:71 level=info key=val
ts=2024-04-16T08:41:25.002492391Z caller=level.go:71 level=warn key=val
ts=2024-04-16T08:41:25.002495287Z caller=level.go:71 level=error key=val
```