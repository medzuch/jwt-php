<?php

declare(strict_types=1);

namespace Medzuch\Jwt\Tests\Unit\Diagnostics;

use Medzuch\Jwt\Diagnostics\LogLevels;
use Medzuch\Jwt\Diagnostics\SecurityLog;
use Medzuch\Jwt\Exception\ExpiredException;
use Medzuch\Jwt\Exception\InvalidAudienceException;
use Medzuch\Jwt\Exception\InvalidClaimException;
use Medzuch\Jwt\Exception\JwksResolutionException;
use Medzuch\Jwt\Exception\SignatureVerificationException;
use Medzuch\Jwt\Tests\Support\SpyLogger;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Psr\Log\LogLevel;
use ReflectionMethod;

#[CoversClass(SecurityLog::class)]
#[\PHPUnit\Framework\Attributes\UsesClass(LogLevels::class)]
final class SecurityLogTest extends TestCase
{
    public function testNullLoggerIsANoOp(): void
    {
        $log = SecurityLog::for(null, null);

        // None of these should error or do anything observable.
        $log->tokenAccepted('k1', 'HS256', 'at+jwt', 'access-token');
        $log->verificationFailed(new SignatureVerificationException('x'), 'k1', 'HS256');
        $log->keyResolved('https://i/jwks', 'cache');

        $this->addToAssertionCount(1);
    }

    public function testAcceptedEmitsAtConfiguredLevelWithRedactedContext(): void
    {
        $spy = new SpyLogger();
        $log = SecurityLog::for($spy, new LogLevels(accepted: LogLevel::INFO));

        $log->tokenAccepted('k1', 'HS256', 'at+jwt', 'access-token');

        $record = $spy->last();
        self::assertSame(LogLevel::INFO, $record['level']);
        self::assertSame('JWT accepted', $record['message']);
        self::assertSame(['kid' => 'k1', 'alg' => 'HS256', 'typ' => 'at+jwt', 'profile' => 'access-token'], $record['context']);
    }

    public function testNullContextFieldsAreDropped(): void
    {
        $spy = new SpyLogger();
        $log = SecurityLog::for($spy, null);

        $log->tokenAccepted(null, 'HS256');

        // kid, typ, profile were null → absent; only alg survives.
        self::assertSame(['alg' => 'HS256'], $spy->last()['context']);
    }

    public function testVerificationFailedRecordsReasonShortClassNotMessage(): void
    {
        $spy = new SpyLogger();
        $log = SecurityLog::for($spy, null);

        $log->verificationFailed(new SignatureVerificationException('secret detail in message'), 'k1', 'HS256', 'access-token');

        $record = $spy->last();
        self::assertSame(LogLevel::WARNING, $record['level']);
        self::assertSame('JWT signature verification failed', $record['message']);
        self::assertSame(
            ['kid' => 'k1', 'alg' => 'HS256', 'profile' => 'access-token', 'reason' => 'SignatureVerificationException'],
            $record['context'],
        );
        // The raw (potentially value-bearing) message is never emitted.
        self::assertStringNotContainsStringIgnoringCase('secret detail', json_encode($record, JSON_THROW_ON_ERROR));
    }

    public function testClaimRejectedNamesTheClaimFromExceptionType(): void
    {
        $spy = new SpyLogger();
        $log = SecurityLog::for($spy, null);

        $log->claimRejected(new ExpiredException('expired at ...'), 'k1', 'HS256', 'access-token');

        $record = $spy->last();
        self::assertSame(LogLevel::NOTICE, $record['level']);
        self::assertSame('JWT claim rejected', $record['message']);
        self::assertSame(
            ['kid' => 'k1', 'alg' => 'HS256', 'profile' => 'access-token', 'claim' => 'exp', 'reason' => 'ExpiredException'],
            $record['context'],
        );
    }

    public function testClaimRejectedMapsAudienceException(): void
    {
        $spy = new SpyLogger();
        $log = SecurityLog::for($spy, null);

        $log->claimRejected(new InvalidAudienceException('no aud'));

        self::assertSame('aud', $spy->last()['context']['claim']);
    }

    public function testClaimRejectedOmitsClaimWhenNotMappable(): void
    {
        $spy = new SpyLogger();
        $log = SecurityLog::for($spy, null);

        // InvalidClaimException is a generic claim failure with no single
        // associated claim name.
        $log->claimRejected(new InvalidClaimException('profile rule'));

        self::assertArrayNotHasKey('claim', $spy->last()['context']);
        self::assertSame('InvalidClaimException', $spy->last()['context']['reason']);
    }

    public function testDecryptionEvents(): void
    {
        $spy = new SpyLogger();
        $log = SecurityLog::for($spy, null);

        $log->tokenDecrypted('k1', 'RSA-OAEP', 'A256GCM');
        self::assertSame('JWE decrypted', $spy->last()['message']);
        self::assertSame(['kid' => 'k1', 'alg' => 'RSA-OAEP', 'enc' => 'A256GCM'], $spy->last()['context']);

        $log->decryptionFailed(new SignatureVerificationException('x'), 'k7', 'dir', 'A128GCM');
        self::assertSame(LogLevel::WARNING, $spy->last()['level']);
        self::assertSame('JWE decryption failed', $spy->last()['message']);
        self::assertSame(['kid' => 'k7', 'alg' => 'dir', 'enc' => 'A128GCM', 'reason' => 'SignatureVerificationException'], $spy->last()['context']);
    }

    public function testKeyResolvedEvent(): void
    {
        $spy = new SpyLogger();
        $log = SecurityLog::for($spy, new LogLevels(keyResolution: LogLevel::INFO));

        $log->keyResolved('https://issuer/jwks.json', 'network');

        self::assertSame(LogLevel::INFO, $spy->last()['level']);
        self::assertSame('JWKS resolved', $spy->last()['message']);
        self::assertSame(['jwks_uri' => 'https://issuer/jwks.json', 'source' => 'network'], $spy->last()['context']);
    }

    public function testKeyResolutionFailedEvent(): void
    {
        $spy = new SpyLogger();
        $log = SecurityLog::for($spy, null);

        $log->keyResolutionFailed(new JwksResolutionException('502'), 'https://issuer/jwks.json');

        $record = $spy->last();
        self::assertSame(LogLevel::WARNING, $record['level']);
        self::assertSame('JWKS resolution failed', $record['message']);
        self::assertSame('JwksResolutionException', $record['context']['reason']);
        self::assertSame('https://issuer/jwks.json', $record['context']['jwks_uri']);
    }

    public function testEmitDropsContextKeysOutsideTheAllowlist(): void
    {
        // White-box guard on the redaction barrier: even if a future caller
        // routed a sensitive field through emit(), the allowlist strips it.
        $spy = new SpyLogger();
        $log = SecurityLog::for($spy, null);

        $emit = new ReflectionMethod($log, 'emit');
        $emit->invoke($log, LogLevel::DEBUG, 'test', [
            'alg' => 'HS256',      // allowed → kept
            'sub' => 'user-123',   // not allowed → dropped
            'token' => 'eyJ...',   // not allowed → dropped
            'kid' => null,         // null → dropped
        ]);

        self::assertSame(['alg' => 'HS256'], $spy->last()['context']);
    }
}
