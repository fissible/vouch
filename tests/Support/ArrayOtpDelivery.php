<?php

declare(strict_types=1);

namespace Fissible\Vouch\Tests\Support;

use DateTimeImmutable;
use Fissible\Vouch\Contracts\OtpDelivery;
use Fissible\Vouch\Models\AuthIdentifier;

/**
 * Captures delivered codes so tests can assert on what was actually sent.
 *
 * A real double rather than a mock: the assertions that matter here are about
 * WHICH identifier received WHICH code, and a mock verifying "deliver was
 * called once" would pass while sending to the wrong address.
 */
final class ArrayOtpDelivery implements OtpDelivery
{
    /** @var list<array{identifier: AuthIdentifier, code: string, expiresAt: DateTimeImmutable}> */
    public array $sent = [];

    public function deliver(AuthIdentifier $identifier, string $code, DateTimeImmutable $expiresAt): void
    {
        $this->sent[] = ['identifier' => $identifier, 'code' => $code, 'expiresAt' => $expiresAt];
    }

    public function lastCode(): string
    {
        return $this->sent[count($this->sent) - 1]['code'];
    }

    public function lastIdentifier(): AuthIdentifier
    {
        return $this->sent[count($this->sent) - 1]['identifier'];
    }
}
