<?php

declare(strict_types=1);

namespace Medzuch\Jwt\PHPStan;

use PhpParser\Node;
use PhpParser\Node\Expr\BinaryOp;
use PhpParser\Node\Expr\MethodCall;
use PhpParser\Node\Expr\NullsafeMethodCall;
use PhpParser\Node\Expr\NullsafePropertyFetch;
use PhpParser\Node\Expr\PropertyFetch;
use PhpParser\Node\Expr\StaticCall;
use PhpParser\Node\Expr\Variable;
use PhpParser\Node\Identifier;
use PHPStan\Analyser\Scope;
use PHPStan\Rules\Rule;
use PHPStan\Rules\RuleErrorBuilder;

/**
 * Custom PHPStan rule enforcing threat-model item **T12 (timing side-channels)**
 * from docs/02-threat-model.md: signature, MAC, and authentication-tag bytes
 * must never be compared with PHP's variable-time `===`/`!==`/`==`/`!=`
 * operators — those short-circuit at the first differing byte and leak how much
 * of a forged tag was correct. Such comparisons must go through
 * {@see \Medzuch\Jwt\Primitives\ConstantTime::equals()} (or `hash_equals()`),
 * which compares in time independent of the first mismatch.
 *
 * The library already routes every such comparison correctly; this rule is a
 * regression guard against a future `if ($expectedSignature === $provided)`
 * slipping in.
 *
 * Heuristic, kept deliberately low-noise: an operand is flagged only when it is
 *   1. **string-typed** (byte strings — not `=== null`, `=== ''`, length ints,
 *      or `=== []` presence/sentinel checks, which are skipped), and
 *   2. **named** like signature/MAC material (`signature`, `sig`, `mac`,
 *      `hmac`, `tag`, `digest`, `checksum`), matched at word granularity so
 *      `signatures`/`signing` do not trip it.
 *
 * Genuinely non-secret values that happen to match (e.g. a structural ASN.1
 * DER tag byte) are whitelisted via `ignoreErrors` in `phpstan.neon.dist` with
 * a documented reason.
 *
 * @implements Rule<BinaryOp>
 */
final class ConstantTimeComparisonRule implements Rule
{
    /**
     * Word-granularity identifiers that denote signature/MAC/tag material.
     *
     * @var list<string>
     */
    private const SENSITIVE_WORDS = ['signature', 'sig', 'mac', 'hmac', 'tag', 'digest', 'checksum'];

    public function getNodeType(): string
    {
        return BinaryOp::class;
    }

    public function processNode(Node $node, Scope $scope): array
    {
        if (
            !$node instanceof BinaryOp\Identical
            && !$node instanceof BinaryOp\NotIdentical
            && !$node instanceof BinaryOp\Equal
            && !$node instanceof BinaryOp\NotEqual
        ) {
            return [];
        }

        $left = $node->left;
        $right = $node->right;

        // Comparisons against a constant literal are presence/sentinel checks
        // ($sig === '', $tag === null, $signatures === []), not content
        // comparisons — never a timing concern.
        if (self::isLiteral($left) || self::isLiteral($right)) {
            return [];
        }

        // Only byte-string comparisons can leak via early-exit; length/flag
        // comparisons are not string-typed and are ignored.
        if (!$scope->getType($left)->isString()->yes() || !$scope->getType($right)->isString()->yes()) {
            return [];
        }

        $sensitive = self::sensitiveName($left) ?? self::sensitiveName($right);
        if ($sensitive === null) {
            return [];
        }

        return [
            RuleErrorBuilder::message(sprintf(
                'Variable-time comparison (%s) of likely signature/MAC value "%s"; '
                . 'use ConstantTime::equals() / hash_equals() to avoid a timing side-channel (threat-model T12).',
                $node->getOperatorSigil(),
                $sensitive,
            ))
                ->identifier('jwtPhp.constantTimeComparison')
                ->build(),
        ];
    }

    private static function isLiteral(Node $expr): bool
    {
        return $expr instanceof Node\Scalar
            || $expr instanceof Node\Expr\ConstFetch   // null / true / false
            || $expr instanceof Node\Expr\Array_;       // []
    }

    /**
     * The identifier of an operand if it names signature/MAC material, else
     * null. Looks at the variable, property, or (method) call name and matches
     * at word granularity, so `$signatures` / `$signing` do not match.
     */
    private static function sensitiveName(Node $expr): ?string
    {
        $name = self::identifierOf($expr);
        if ($name === null) {
            return null;
        }

        foreach (self::words($name) as $word) {
            if (in_array($word, self::SENSITIVE_WORDS, true)) {
                return $name;
            }
        }

        return null;
    }

    private static function identifierOf(Node $expr): ?string
    {
        if ($expr instanceof Variable && is_string($expr->name)) {
            return $expr->name;
        }

        if (
            ($expr instanceof PropertyFetch
                || $expr instanceof NullsafePropertyFetch
                || $expr instanceof MethodCall
                || $expr instanceof NullsafeMethodCall
                || $expr instanceof StaticCall)
            && $expr->name instanceof Identifier
        ) {
            return $expr->name->toString();
        }

        return null;
    }

    /**
     * Split an identifier into lowercased words on snake_case and camelCase
     * boundaries: `expectedTag` -> [expected, tag], `provided_mac` -> [provided, mac].
     *
     * @return list<string>
     */
    private static function words(string $identifier): array
    {
        $parts = preg_split('/(?<=[a-z0-9])(?=[A-Z])|[_\s]+/', $identifier);
        if ($parts === false) {
            $parts = [$identifier];
        }

        return array_values(array_map('strtolower', array_filter($parts, static fn(string $p): bool => $p !== '')));
    }
}
