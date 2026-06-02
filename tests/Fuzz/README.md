# Fuzzing

Coverage-guided fuzzing of the parsers that touch **untrusted input**, using
[`nikic/php-fuzzer`](https://github.com/nikic/PHP-Fuzzer). Part of the Phase 5
hardening (see `docs/07-testing-strategy.md`).

## The contract under test

Every target asserts one invariant via `setAllowedExceptions([JwtException::class])`:

> A parser fed arbitrary bytes must reject them with a **`JwtException`** and
> nothing else.

Any other `Throwable` escaping — an `Error`, `TypeError`, `ValueError`,
`JsonException`, or a raw SPL exception — is a bug. **Triage priority: any such
crash is P0.**

## Targets (`targets/`)

| Target | Entry point |
|--------|-------------|
| `jwt_parser` | `JwtParser::parse()` |
| `json_decode` | `Json::decode()` |
| `base64url_decode` | `Base64Url::decode()` |
| `jws_compact` | `Jws\CompactSerializer::deserialize()` |
| `jwe_compact` | `Jwe\CompactSerializer::deserialize()` |
| `jws_json` | `Jws\JsonSerializer::deserialize()` |
| `jwe_json` | `Jwe\JsonSerializer::deserialize()` |

## Corpus model

- `seeds/<target>/` — small, hand-picked, **committed** seed inputs.
- `var/fuzz/<target>/` — the mutable working corpus the fuzzer grows
  (**git-ignored**; cached between nightly CI runs so coverage accumulates).

`run.sh` copies the seeds into the working corpus before each run, so the
committed seeds are never polluted.

## Running

```sh
# In Docker (preferred):
make fuzz TARGET=jwt_parser RUNS=200000     # bounded
make fuzz TARGET=json_decode                # unbounded (Ctrl-C to stop)

# Directly:
sh tests/Fuzz/run.sh jwt_parser 200000
```

Reproduce / shrink a crash:

```sh
vendor/bin/php-fuzzer run-single tests/Fuzz/targets/jwt_parser.php crash-<hash>.txt
vendor/bin/php-fuzzer minimize-crash tests/Fuzz/targets/jwt_parser.php crash-<hash>.txt
```

## CI

`.github/workflows/fuzz.yml` runs every target nightly, time-boxed, with a
cached corpus. On a crash it uploads the input as an artifact and files a
de-duplicated **P0** issue (`report-crash.sh`). The Phase 5 exit gate is one
clean week of nightly runs with no novel crashes.
