# Configuration Reference

The service reads its runtime configuration from `config.yaml` in the
repository root. Unknown keys are ignored with a warning.

## Timeouts

The `request_timeout` must be a positive integer number of seconds. The
default value is 30 seconds.

## Deprecated options

The `legacy_mode` flag is not applicable to version 3 and later. Setting it
has no effect and it will be removed in a future release.

## Environment

The `LOG_LEVEL` variable controls verbosity. Supported values are `debug`,
`info`, `warning`, and `error`.
