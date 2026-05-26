<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Algorithm\KeyManagement\Internal;

/**
 * The Concat KDF (NIST SP 800-56A §5.8.1) as profiled by JOSE for ECDH-ES
 * (RFC 7518 §4.6.2): SHA-256 is the hash, and `OtherInfo` is the
 * concatenation of four length-prefixed / fixed-width fields —
 *
 *   AlgorithmID || PartyUInfo || PartyVInfo || SuppPubInfo
 *
 * where AlgorithmID/PartyUInfo/PartyVInfo are each a 32-bit big-endian length
 * followed by that many octets, and SuppPubInfo is the key-data length in
 * bits as a 32-bit big-endian integer (SuppPrivInfo is empty for JOSE).
 *
 * The derived keying material is `Hash(counter || Z || OtherInfo)` for
 * counter = 1, 2, … concatenated and truncated to the requested length; for
 * the JOSE key sizes (≤ 512 bits) this is one or two SHA-256 rounds.
 *
 * @internal consumed by the ECDH-ES key-management algorithms only
 */
final class ConcatKdf
{
    private const HASH_LENGTH_BYTES = 32;

    /** @codeCoverageIgnore */
    private function __construct() {}

    /**
     * @param string       $z            the raw ECDH shared secret
     * @param positive-int  $keyBytes     desired derived-key length in bytes
     * @param string       $algorithmId  the `enc` (direct) or `alg` (key wrapping) value
     * @param string       $partyUInfo   decoded `apu`, or the empty string
     * @param string       $partyVInfo   decoded `apv`, or the empty string
     *
     * @return non-empty-string
     */
    public static function derive(string $z, int $keyBytes, string $algorithmId, string $partyUInfo = '', string $partyVInfo = ''): string
    {
        $otherInfo = self::lengthPrefixed($algorithmId)
            . self::lengthPrefixed($partyUInfo)
            . self::lengthPrefixed($partyVInfo)
            . pack('N', $keyBytes * 8);

        // @infection-ignore-all — the `- 1` is the ceil-division idiom; for the
        // JOSE key sizes (16/24/32/48/64) perturbing it only ever rounds *up*,
        // and the surplus round is discarded by the truncation below, so the
        // arithmetic mutants are equivalent.
        $reps = intdiv($keyBytes + self::HASH_LENGTH_BYTES - 1, self::HASH_LENGTH_BYTES);

        $output = '';
        for ($counter = 1; $counter <= $reps; ++$counter) {
            $output .= hash('sha256', pack('N', $counter) . $z . $otherInfo, true);
        }

        $derived = substr($output, 0, $keyBytes);

        /** @var non-empty-string $derived */
        return $derived;
    }

    private static function lengthPrefixed(string $data): string
    {
        return pack('N', strlen($data)) . $data;
    }
}
