<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Tests\Support;

/**
 * Deterministic generator of hostile, structure-aware byte strings for the
 * property-based parser invariant tests ({@see \Medzuch\Jwt\Tests\Property}).
 *
 * This is the fast, always-on, in-suite cousin of the coverage-guided nightly
 * fuzzer (tests/Fuzz). Where the fuzzer explores the input space with feedback
 * over a long wall-clock budget, this generator produces a fixed, reproducible
 * sequence from a seed so a failing input can be replayed exactly. Each
 * {@see next()} picks one generation strategy and returns a single input.
 *
 * The strategies range from pure noise (which mostly bounces off the outer
 * length/format guards) to structure-aware inputs — dotted segment lists,
 * base64url-wrapped JSON built from real JOSE member names, and bit-flipped
 * mutations of shaped tokens — which is what drives execution deep into the
 * parsers where the interesting bugs live.
 */
final class HostileInputGenerator
{
    /**
     * JOSE / JWT vocabulary — member names and values the real parsers branch
     * on. Mirrors tests/Fuzz/jose.dict so both harnesses probe the same space.
     *
     * @var list<string>
     */
    private const VOCAB = [
        'alg', 'enc', 'kid', 'typ', 'cty', 'crit', 'b64', 'zip', 'jku', 'jwk',
        'x5c', 'x5t', 'x5u', 'x5t#S256', 'epk', 'apu', 'apv', 'p2s', 'p2c',
        'iv', 'tag', 'aad', 'payload', 'protected', 'header', 'signature',
        'signatures', 'ciphertext', 'recipients', 'encrypted_key', 'unprotected',
        'HS256', 'HS384', 'HS512', 'RS256', 'PS256', 'ES256', 'ES384', 'ES512',
        'EdDSA', 'none', 'A128GCM', 'A256GCM', 'A128CBC-HS256', 'A256CBC-HS512',
        'RSA-OAEP', 'RSA-OAEP-256', 'ECDH-ES', 'ECDH-ES+A128KW', 'A256KW', 'dir',
        'JWT', 'iss', 'sub', 'aud', 'exp', 'nbf', 'iat', 'jti',
        'true', 'false', 'null', '{}', '[]', '""', '0', '-1', '1e999',
    ];

    /**
     * Shaped-but-fake tokens used as mutation seeds. Signatures are bogus —
     * structural deserialization never verifies crypto, so these still drive
     * the parsers all the way through. Covers compact JWS/JWT, compact JWE
     * (5 segments) and flattened/general JSON serializations.
     *
     * @var list<string>
     */
    private const TEMPLATES = [
        // Compact JWS / JWT: {"alg":"HS256","typ":"JWT"} . {"sub":"x"} . sig
        'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ4In0.c2ln',
        // alg:none, empty signature
        'eyJhbGciOiJub25lIn0.eyJzdWIiOiJ4In0.',
        // Compact JWE: header.encrypted_key.iv.ciphertext.tag
        'eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4R0NNIn0..aXY.Y3Q.dGFn',
        // Flattened JSON JWS
        '{"payload":"eyJzdWIiOiJ4In0","protected":"eyJhbGciOiJIUzI1NiJ9","signature":"c2ln"}',
        // General JSON JWS, two signatures
        '{"payload":"eyJzdWIiOiJ4In0","signatures":[{"protected":"eyJhbGciOiJIUzI1NiJ9","signature":"c2ln"},{"protected":"eyJhbGciOiJIUzM4NCJ9","header":{"kid":"k2"},"signature":"c2ln2"}]}',
        // RFC 7797 b64:false detached-ish
        '{"payload":"$.02","protected":"eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19","signature":"c2ln"}',
    ];

    /** Internal xorshift32 state; non-zero. Set by {@see seed()}. */
    private int $state = 0x9E3779B9;

    public function __construct(private readonly int $maxLen = 512) {}

    /**
     * Seed the generator so a run is fully reproducible from its seed. Uses a
     * private xorshift PRNG rather than the global Mersenne Twister: no global
     * side effects, and the sequence is pinned to this class regardless of the
     * surrounding PHP RNG state. Call once before a batch of {@see next()}.
     */
    public function seed(int $seed): void
    {
        // xorshift32 degenerates at 0; map it to a fixed non-zero constant.
        $masked = $seed & 0xFFFFFFFF;
        $this->state = $masked !== 0 ? $masked : 0x9E3779B9;
    }

    /**
     * Produce one hostile input by picking a strategy uniformly at random.
     */
    public function next(): string
    {
        return match ($this->rand(0, 6)) {
            0 => $this->randomBytes(),
            1 => $this->randomAscii(),
            2 => $this->dottedSegments(),
            3 => $this->jsonish(),
            4 => $this->base64urlJson(),
            default => $this->mutatedTemplate(),
        };
    }

    /** Arbitrary bytes, including NUL and the high range. */
    private function randomBytes(): string
    {
        $len = $this->rand(0, $this->maxLen);
        $out = '';
        for ($i = 0; $i < $len; ++$i) {
            $out .= chr($this->rand(0, 255));
        }

        return $out;
    }

    /** Printable ASCII noise — exercises the textual format guards. */
    private function randomAscii(): string
    {
        $len = $this->rand(0, $this->maxLen);
        $out = '';
        for ($i = 0; $i < $len; ++$i) {
            $out .= chr($this->rand(0x20, 0x7E));
        }

        return $out;
    }

    /**
     * A dot-delimited list of 1–6 segments, each empty, base64url noise, or raw
     * garbage. Targets the compact segment-splitting logic (2/3/5-part shapes).
     */
    private function dottedSegments(): string
    {
        $count = $this->rand(1, 6);
        $segments = [];
        for ($i = 0; $i < $count; ++$i) {
            $segments[] = match ($this->rand(0, 3)) {
                0 => '',
                1 => $this->base64urlNoise($this->rand(0, 64)),
                2 => $this->token(),
                default => $this->randomAscii(),
            };
        }

        return implode('.', $segments);
    }

    /** JSON-ish text: balanced-ish braces, quotes, and JOSE keywords. */
    private function jsonish(): string
    {
        $parts = ['{', '[', '}', ']', ':', ',', '"', '\\', "\xC3\x28" /* bad UTF-8 */];
        $len = $this->rand(0, 60);
        $out = '';
        for ($i = 0; $i < $len; ++$i) {
            $out .= $this->rand(0, 1) === 0 ? $this->token() : $parts[$this->rand(0, count($parts) - 1)];
        }

        return $out;
    }

    /** base64url of a random JSON object assembled from JOSE member names. */
    private function base64urlJson(): string
    {
        $pairs = $this->rand(0, 5);
        $obj = [];
        for ($i = 0; $i < $pairs; ++$i) {
            $obj[$this->token()] = match ($this->rand(0, 4)) {
                0 => $this->token(),
                1 => $this->rand(-1000, 1000),
                2 => (bool) $this->rand(0, 1),
                3 => [$this->token(), $this->token()],
                default => null,
            };
        }

        $json = json_encode($obj);
        if ($json === false) {
            $json = '{}';
        }

        return $this->base64urlEncode($json);
    }

    /**
     * Take a shaped template and corrupt it: bit flips, truncation, byte
     * insertion, or segment duplication. Keeps the input close enough to valid
     * that it reaches deep parser state before tripping a guard.
     */
    private function mutatedTemplate(): string
    {
        $s = self::TEMPLATES[$this->rand(0, count(self::TEMPLATES) - 1)];
        $rounds = $this->rand(1, 8);
        for ($i = 0; $i < $rounds && $s !== ''; ++$i) {
            $pos = $this->rand(0, strlen($s) - 1);
            $s = match ($this->rand(0, 4)) {
                0 => substr($s, 0, $pos) . chr($this->rand(0, 255)) . substr($s, $pos + 1), // overwrite
                1 => substr($s, 0, $pos) . substr($s, $pos + 1),                          // delete
                2 => substr($s, 0, $pos),                                                 // truncate
                3 => substr($s, 0, $pos) . chr($this->rand(0x20, 0x7E)) . substr($s, $pos),   // insert
                default => $s . '.' . substr($s, $pos),                                   // extra segment
            };
        }

        return $s;
    }

    private function token(): string
    {
        return self::VOCAB[$this->rand(0, count(self::VOCAB) - 1)];
    }

    /**
     * Deterministic uniform-ish integer in [$min, $max], driven by a private
     * xorshift32 PRNG. A small modulo bias is irrelevant for input generation;
     * reproducibility from the seed is what matters. The `& 0xFFFFFFFF` masking
     * assumes a 64-bit PHP build (on 32-bit the shifts would overflow to float);
     * the library targets PHP 8.3 on 64-bit platforms, so this is safe.
     */
    private function rand(int $min, int $max): int
    {
        $x = $this->state;
        $x ^= ($x << 13) & 0xFFFFFFFF;
        $x ^= $x >> 17;
        $x ^= ($x << 5) & 0xFFFFFFFF;
        $this->state = $x & 0xFFFFFFFF;

        return $min + ($this->state % ($max - $min + 1));
    }

    private function base64urlNoise(int $len): string
    {
        $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_=';
        $out = '';
        for ($i = 0; $i < $len; ++$i) {
            $out .= $alphabet[$this->rand(0, strlen($alphabet) - 1)];
        }

        return $out;
    }

    private function base64urlEncode(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }
}
