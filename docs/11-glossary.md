# 11 — Glossary

A reference for the JOSE terminology used throughout the docs and code.
Where possible, terms are defined as in the source RFCs.

## A

**`aud` (Audience).** A claim identifying the recipients the JWT is
intended for. Case-sensitive. Each principal processing the JWT must
match itself against one of the values. (RFC 7519 §4.1.3)

**Algorithm allowlist.** The set of `alg` values a validator is willing
to accept. Mandatory in this library. (RFC 8725 §3.1)

**Algorithm family.** Grouping of related algorithms: HMAC, RSA, RSA-PSS,
ECDSA, EdDSA, key-encryption, content-encryption, key-agreement, NONE.

**`alg` Header Parameter.** Names the algorithm used to secure the JWS or
JWE. Untrusted in this library — the caller's allowlist decides what is
acceptable, and the key/algorithm binding decides whether the asserted
`alg` is even possible for the available key.

## B

**`b64` Header Parameter.** Boolean introduced by RFC 7797 controlling
whether the JWS payload is base64url-encoded for signing. Default `true`.
**Forbidden in JWTs** per RFC 7797 §7 (updates RFC 7519).

**Base64url.** The URL-safe base64 variant defined in RFC 4648 §5, with
trailing `=` padding stripped per RFC 7515 §2. Distinct from RFC 4648 §4
("base64") in that `+` becomes `-` and `/` becomes `_`.

**BCP.** Best Current Practice — IETF document type. RFC 8725 is BCP 225.

## C

**Claim.** A name/value pair asserted about the subject of a JWT. Names
are strings; values are any JSON value. (RFC 7519 §2)

**ClaimsSet.** The JSON object that contains all the claims. In code,
the immutable DTO returned by validation.

**Compact Serialization.** The dot-separated form of a JWS or JWE used
in JWTs: `base64url(header).base64url(payload).base64url(signature)`.

**`crit` Header Parameter.** A list of header parameter names that must
be understood by the receiver, or the JWS must be rejected. Required
with `b64:false` per RFC 7797 §6.

**`cty` (Content Type).** Declares the content type of the payload.
For nested JWTs, must be `"JWT"`. (RFC 7519 §5.2)

## D

**Detached payload.** A JWS where the payload is transmitted out-of-band
and the middle segment of the compact form is empty. Common with
`b64:false`. (RFC 7515 Appendix F)

## E

**ECDH-ES.** Elliptic Curve Diffie-Hellman Ephemeral Static key
agreement, used in JWE. Vulnerable to invalid-curve attacks if input
validation is missed. (RFC 7518 §4.6)

**EdDSA.** Edwards-curve Digital Signature Algorithm. The library uses
Ed25519 via libsodium.

**`exp` (Expiration Time).** Numeric date after which the JWT is invalid.
(RFC 7519 §4.1.4)

## H

**Header Parameter.** A member of the JOSE Header. Some are protected
(integrity-covered), some are unprotected (JWE/JSON Serialization only).

**HMAC.** Hash-based Message Authentication Code. In JOSE: HS256, HS384,
HS512.

## I

**`iat` (Issued At).** Numeric date the JWT was issued. (RFC 7519 §4.1.6)

**Integrity-protected.** Covered by the signature/MAC. The protected
header is; the payload always is; the unprotected JWE header is not.

**`iss` (Issuer).** Case-sensitive string or URI identifying the
principal that issued the JWT. (RFC 7519 §4.1.1)

## J

**JOSE.** JavaScript Object Signing and Encryption — the IETF working
group and the umbrella term for JWS/JWE/JWK/JWA/JWT.

**JOSE Header.** The first segment of a JWS/JWE compact form. A JSON
object whose members describe the cryptographic operations.

**`jku` (JWK Set URL).** Header that points to a JWKS document. **Never
auto-followed** in this library.

**`jti` (JWT ID).** Unique identifier for the JWT. Useful for replay
prevention. (RFC 7519 §4.1.7)

**JWA.** JSON Web Algorithms (RFC 7518). Catalogue of algorithm
identifiers.

**JWE.** JSON Web Encryption (RFC 7516). Confidentiality and integrity
via authenticated encryption.

**JWK.** JSON Web Key (RFC 7517). A JSON representation of a key.

**JWKS.** A JWK Set — a JSON document with a `keys` array.

**JWS.** JSON Web Signature (RFC 7515). Integrity and authenticity via
signature or MAC.

**JWT.** JSON Web Token (RFC 7519). A JWS or JWE whose payload is a JSON
object of claims, serialized in compact form.

## K

**`kid` (Key ID).** Hint to help the receiver find the right key. Must
be treated as untrusted input. (RFC 7515 §4.1.4)

**`key_ops`.** Permitted operations for a JWK. Mutually exclusive with
some uses of `use`.

## N

**`nbf` (Not Before).** Numeric date before which the JWT is invalid.
(RFC 7519 §4.1.5)

**Nested JWT.** A JWT used as the payload of another JWS or JWE.
Always sign first, then encrypt. (RFC 7519 §11.2)

**`none` algorithm.** An "unsecured" mode with empty signature. Refused
by default in this library.

**NumericDate.** Seconds since 1970-01-01T00:00:00Z UTC. (RFC 7519 §2)

## O

**OKP.** Octet Key Pair, the key type used for Ed25519/X25519/Ed448/X448.

## P

**Profile.** In this library, a pre-configured validator for a specific
application context (access token, ID token, SET).

**Protected Header.** The integrity-protected portion of a JOSE header.
Required content for all `crit`-flagged headers.

## R

**Registered Claim Name.** A claim defined by IANA in the JSON Web Token
Claims registry. Examples: `iss`, `sub`, `aud`, `exp`, `nbf`, `iat`,
`jti`.

**Replay attack.** Reuse of a previously valid token. Mitigation:
short-lived `exp`, `jti` blocklists, audience binding.

## S

**SET.** Security Event Token (RFC 8417). A JWT carrying security event
information, with `typ` of `secevent+jwt`.

**Substitution attack.** Using a token in a different context than
intended (different recipient, different protocol). Mitigated by
audience and explicit typing.

**`sub` (Subject).** Case-sensitive string or URI identifying the
principal that is the subject of the claims. (RFC 7519 §4.1.2)

## T

**`typ` (Type).** Header parameter declaring the media type of the
complete JWT. Used for explicit typing (RFC 8725 §3.11), e.g. `at+jwt`,
`id+jwt`, `secevent+jwt`.

## U

**Unsecured JWT.** A JWT using `alg:none`. Refused by default; available
through a separate API path.

**UTF-8.** The mandatory encoding for everything in JOSE (RFC 8725 §3.7).
Validated explicitly by `Primitives\Utf8`.

## X

**`x5c` / `x5u` / `x5t`.** Header parameters carrying or pointing to
X.509 certificates. `x5u` is not auto-followed by default for the same
SSRF reasons as `jku`.
