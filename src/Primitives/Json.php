<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Primitives;

use JsonException;
use Medzuch\Jwt\Exception\MalformedJwtException;

/**
 * UTF-8-only JSON encode/decode with top-level duplicate-key rejection
 * and bounded depth.
 *
 * Mitigates:
 *   - T13 (duplicate claim names, RFC 7519 §4): json_decode silently keeps
 *     the last occurrence; we walk the source bytes first and refuse any
 *     duplicate key at the **root object**. JWT headers and claim sets are
 *     where smuggling matters (registered claims like `aud`, `iss`, `exp`
 *     live at depth 0). Nested objects are application data; if an app
 *     stores security-relevant claims inside one, it is responsible for
 *     validating them.
 *   - T7 (multi-encoding ambiguity, RFC 8725 §3.7): rejects non-UTF-8 input,
 *     including BOMs.
 *   - Stack-blowup via deeply nested JSON: depth bound applied to decode.
 */
final class Json
{
    /**
     * Decode depth bound. JWT headers and claim sets are shallow; 32 is plenty
     * and keeps catastrophic inputs from chewing call stack.
     */
    public const MAX_DEPTH = 32;

    /** @codeCoverageIgnore */
    private function __construct() {}

    /**
     * Decode a JSON object.
     *
     * @return array<string, mixed>
     *
     * @throws MalformedJwtException
     */
    public static function decode(string $bytes): array
    {
        Utf8::assertValid($bytes);
        self::assertNoDuplicateTopLevelKeys($bytes);

        try {
            /** @var mixed $decoded */
            $decoded = json_decode($bytes, true, self::MAX_DEPTH, JSON_THROW_ON_ERROR);
        } catch (JsonException $e) {
            throw new MalformedJwtException('Invalid JSON: ' . $e->getMessage(), 0, $e);
        }

        if (!self::isStringKeyedArray($decoded)) {
            throw new MalformedJwtException('JSON root must be an object');
        }

        return $decoded;
    }

    /**
     * Encode a JSON object back to bytes.
     *
     * Slashes and unicode are left untouched (RFC 7515 examples use this
     * form, and it keeps the output a single canonical representation).
     *
     * @param array<string, mixed> $data
     *
     * @throws MalformedJwtException
     */
    public static function encode(array $data): string
    {
        try {
            return json_encode(
                $data,
                JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE,
            );
        } catch (JsonException $e) {
            throw new MalformedJwtException('Cannot encode value as JSON: ' . $e->getMessage(), 0, $e);
        }
    }

    /**
     * Scan the root object for duplicate keys.
     *
     * Walks one nesting level only: every string at depth 1 (immediately
     * inside the root `{`) that appears in key position is collected; a
     * repeat throws. Nested containers are skipped wholesale via brace/
     * bracket counting, so we never look at inner keys.
     *
     * Anything that is not a syntactically valid root object is left to
     * `json_decode` to reject afterwards — this function only cares about
     * duplicates.
     *
     * @throws MalformedJwtException
     */
    private static function assertNoDuplicateTopLevelKeys(string $json): void
    {
        $len = strlen($json);
        $i = self::skipWhitespace($json, 0, $len);

        if ($i >= $len || $json[$i] !== '{') {
            return; // not an object — json_decode below will reject
        }
        ++$i;

        /** @var array<string, true> $seen */
        $seen = [];
        $expectingKey = true;
        $depth = 1;

        while ($i < $len && $depth > 0) {
            $c = $json[$i];

            if ($c === ' ' || $c === "\t" || $c === "\n" || $c === "\r") {
                ++$i;

                continue;
            }

            if ($c === '"') {
                $end = self::scanStringEnd($json, $i + 1, $len);

                if ($expectingKey && $depth === 1) {
                    self::recordKey($json, $i, $end, $seen);
                }

                $i = $end + 1;

                continue;
            }

            if ($c === '{' || $c === '[') {
                ++$depth;
                $expectingKey = false;
                ++$i;

                continue;
            }

            if ($c === '}' || $c === ']') {
                --$depth;
                ++$i;

                continue;
            }

            if ($c === ':') {
                $expectingKey = false;
                ++$i;

                continue;
            }

            if ($c === ',' && $depth === 1) {
                $expectingKey = true;
                ++$i;

                continue;
            }

            ++$i;
        }
    }

    /**
     * @param array<string, true> $seen
     *
     * @param-out array<string, true> $seen
     *
     * @throws MalformedJwtException
     */
    private static function recordKey(string $json, int $openQuote, int $closeQuote, array &$seen): void
    {
        $raw = substr($json, $openQuote, $closeQuote - $openQuote + 1);

        try {
            /** @var mixed $key */
            $key = json_decode($raw, false, 2, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            // Malformed escape — outer json_decode will reject the document.
            return;
        }

        // @codeCoverageIgnoreStart
        // Defensive: json_decode of a quoted string yields a string or throws.
        if (!is_string($key)) {
            return;
        }
        // @codeCoverageIgnoreEnd

        if (isset($seen[$key])) {
            throw new MalformedJwtException(sprintf('Duplicate JSON key "%s" (RFC 7519 §4)', $key));
        }
        $seen[$key] = true;
    }

    private static function skipWhitespace(string $json, int $i, int $len): int
    {
        while ($i < $len) {
            $c = $json[$i];
            if ($c !== ' ' && $c !== "\t" && $c !== "\n" && $c !== "\r") {
                return $i;
            }
            ++$i;
        }

        return $i;
    }

    /**
     * Given that $json[$start - 1] is the opening quote of a string, return
     * the index of the closing quote (or $len if the string is unterminated;
     * `json_decode` will then reject the document).
     */
    private static function scanStringEnd(string $json, int $start, int $len): int
    {
        $j = $start;
        while ($j < $len) {
            $ch = $json[$j];
            if ($ch === '\\') {
                $j += 2;

                continue;
            }
            if ($ch === '"') {
                return $j;
            }
            ++$j;
        }

        return $len;
    }

    /**
     * @phpstan-assert-if-true array<string, mixed> $value
     */
    private static function isStringKeyedArray(mixed $value): bool
    {
        if (!is_array($value)) {
            return false;
        }

        foreach (array_keys($value) as $key) {
            if (!is_string($key)) {
                return false;
            }
        }

        return true;
    }
}
