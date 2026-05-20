# 08 — Coding Standards

## Style baseline

`PER-CS` plus the Symfony ruleset, plus the explicit additions in
`.php-cs-fixer.dist.php`. Run `composer cs:fix` before committing.

## PHPStan

Level 9 with strict rules. `treatPhpDocTypesAsCertain` is **on** — your
docblocks count.

Common pitfalls and how we handle them:

| Issue | Resolution |
|-------|------------|
| `mixed` from `json_decode` | Decode through `Primitives\Json::decode`, which returns `array<string, mixed>`. Type narrow with assertions in the caller. |
| Iterables of unknown shape | Use `iterable<TKey, TValue>` in docblocks. PHPStan can verify. |
| `is_object()` narrowing fails | Switch to `instanceof` whenever possible. |
| Crypto byte-string types | We use the alias `non-empty-string` in docblocks for things like signatures and ciphertext where empty would be a bug. |

## Required declarations

Every file:

```php
<?php

declare(strict_types=1);

namespace Medzuch\Jwt\...;
```

`strict_types=1` is enforced by the fixer; missing it is a CS error.

## Final by default

Every class is `final` unless inheritance is part of the public contract
(in which case it's `abstract` with documented extension points).
`Medzuch\Jwt\Key\Key` is abstract; nothing else should be.

## Immutability

DTOs are `readonly` classes. Domain primitives (`ClaimsSet`, `Header`,
`CompactJws`, `ParsedJwt`) never mutate. Builders return new instances
from every `with*` method.

## No silent failures

- No `@` error suppression.
- No `try { ... } catch (\Throwable) { return null; }`.
- No `return false` on error from anything public — throw.

## Naming

| Kind | Convention | Example |
|------|------------|---------|
| Class | PascalCase | `RsaPrivateKey` |
| Interface | PascalCase, no `I` prefix | `Algorithm`, `KeyResolver` |
| Trait | PascalCase, `Trait` suffix only when ambiguous | `HasClaimsTrait` |
| Method | camelCase | `expiresAt()` |
| Property | camelCase | `kid` |
| Constant | UPPER_SNAKE_CASE | `Version::SEMVER` |
| Enum case | PascalCase | `KeyUse::Sig` |

Acronyms are treated as a single word: `JwkSet`, `RsaKey`, `JwsSigner` —
not `JWKSet`, `RSAKey`, `JWSSigner`.

## Methods that return something or throw

Public methods on the safe API never return `null` to indicate "this
didn't work". They either return a meaningful value or throw a typed
exception. Methods that legitimately return optional data (e.g.
`ClaimsSet::issuer(): ?string`) document the `null` case in the docblock.

## Imports

Always import classes, functions, and constants from other namespaces.
The fixer enforces this. Inside a single namespace, no `use` statement
is needed.

```php
use function in_array;
use const JSON_THROW_ON_ERROR;
```

## Strictness with primitives

- Always use `===` and `!==` for non-string comparisons.
- For **signature/ciphertext/MAC** comparisons, use
  `Primitives\ConstantTime::equals`. A static analysis rule (planned,
  Phase 5) flags `===` on byte-string-typed parameters.

## Docblocks

- One sentence summary, then a blank line, then detail.
- `@param`/`@return` only when they add information PHPStan can't infer
  (generic types, array shapes).
- `@throws` for every exception that escapes the method, including
  subclasses. PHPStan checks this.
- Internal classes get `@internal`. Public classes do not need a
  `@public` tag — that's the default.

## Comments inside code

Explain **why**, not **what**. Specifically, prefer comments that:

- Cite an RFC section (e.g. `// RFC 8725 §3.5: 256-bit minimum for HS256`).
- Explain a non-obvious security trade-off.
- Point to a regression test for a fix.

Avoid:

- Restating what the code obviously does.
- TODOs without a linked issue.

## Magic methods

Avoid. They defeat type inference and IDE navigation.

The only allowed magic methods:

- `__construct`, `__destruct`.
- `__toString` on stringable value objects (`CompactJws`).
- `__invoke` on intentional functor classes (rare; document why).

## Static methods

Use sparingly. The two acceptable categories:

1. Named constructors (`HmacKey::fromBinary`, `JwkSet::fromArray`).
2. Pure utility classes whose state is a constant configuration
   (`Primitives\Base64Url::encode`).

If a static method has any I/O, configuration, or branching on global
state, it should be an instance method on an injected service instead.

## Error messages

User-visible error messages:

- Identify the parameter or claim involved.
- Identify the RFC section being enforced when relevant.
- Do **not** include the offending value if it is sensitive (signatures,
  keys, encrypted data). Do include short structural values (claim names,
  algorithm names).

Good:
> `Claim "exp" is missing; required by AccessTokenProfile per RFC 9068 §4.`

Bad:
> `Invalid token: eyJhbGciOiJSUzI1NiIsImtpZ...`

## Logging (Phase 5)

If a logger is injected:

- Failures log at `warning` for client-fault (bad token) and `error` for
  server-fault (key resolver crash).
- Successes log at `debug` only, and only with `kid` and `alg`.
- **Never** log: full token bytes, signatures, plaintext claims (the
  application owns the claims and decides whether to log them).
