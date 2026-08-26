<?php

declare(strict_types=1);

namespace Fissible\Vouch\Enrollment;

use Fissible\Vouch\Kernel\Factor\FactorStrength;
use Fissible\Vouch\Models\AuthCredential;
use Fissible\Vouch\Models\AuthIdentifier;
use Fissible\Vouch\Support\BoundedLockWait;
use Fissible\Vouch\Support\LockContention;
use Fissible\Vouch\Verification\IdentifierVerificationRequest;
use Fissible\Vouch\Verification\IdentifierVerifier;
use Illuminate\Database\Connection;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\Hash;

/**
 * The host-only first-password bootstrap path.
 *
 * The identifier and credential are one guarded transaction.  A failed claim
 * therefore cannot leave a password for a user who owns no identifier.  The
 * ceremony is deliberately issued afterwards: committed claims receive a real
 * ceremony, while every neutral refusal receives an indistinguishable durable
 * decoy. If a contended database cannot persist that decoy inside the explicit
 * lock-wait budget, the contention is surfaced rather than being reported as
 * an indistinguishable success without its durable counterpart.
 *
 * This deliberately writes the password credential here instead of calling
 * PasswordFactor::enroll(). The shared behaviors are a non-empty password,
 * Hash::make(), knowledge strength, the password type, and the one-active-row
 * invariant. The intentionally unshared PasswordFactor::enroll() behaviors
 * are its `replace` flag (bootstrap has no replacement request), disabling all
 * active credentials before creating a new row (bootstrap re-enables its one
 * disabled row), always creating a fresh credential, and returning an
 * EnrollmentResult. This path needs the identifier claim and its idempotent
 * password bootstrap in one transaction on the caller-selected connection;
 * PasswordFactor::enroll() owns a separate enrollment transaction and cannot
 * provide that atomic identifier boundary.
 */
final readonly class FirstCredentialEnrollment
{
    public function __construct(
        private Connection $connection,
        private IdentifierVerifier $verifier,
        private BoundedLockWait $boundedLockWait,
        private LockContention $lockContention,
        private int $lockWaitSeconds,
    ) {}

    public function enroll(FirstCredentialRequest $request): FirstCredentialResult
    {
        $ceremony = new IdentifierVerificationRequest(
            $request->identifierType,
            $request->identifierValue,
            $request->tenantId,
            $request->clientIp,
        );

        try {
            $claimed = $this->write($request);
        } catch (EnrollmentRefused) {
            $this->requestDurableDecoy($ceremony);

            return FirstCredentialResult::Accepted;
        } catch (QueryException $failure) {
            if (! $this->isIdentifierUniqueViolation($failure)) {
                throw $failure;
            }

            $this->requestDurableDecoy($ceremony);

            return FirstCredentialResult::Accepted;
        }

        if ($claimed) {
            $this->verifier->request($ceremony);
        } else {
            $this->requestDurableDecoy($ceremony);
        }

        return FirstCredentialResult::Accepted;
    }

    /**
     * @return bool True only when this user owns the identifier after the write.
     */
    private function write(FirstCredentialRequest $request): bool
    {
        if ($request->password === '') {
            throw new \InvalidArgumentException('First credential enrollment requires a non-empty password credential.');
        }

        $guard = new EnrollmentGuard($this->connection, $this->lockWaitSeconds);
        $connection = $this->connection->getName();

        return $guard->serialize(
            $request->userId,
            'password',
            1,
            function () use ($connection, $request): bool {
                $identifier = AuthIdentifier::on($connection)
                    ->where('type', $request->identifierType)
                    ->where('value', $request->identifierValue)
                    ->first();

                if ($identifier instanceof AuthIdentifier && $identifier->user_id !== $request->userId) {
                    return false;
                }

                if (! $identifier instanceof AuthIdentifier) {
                    AuthIdentifier::on($connection)->create([
                        'user_id' => $request->userId,
                        'type' => $request->identifierType,
                        'value' => $request->identifierValue,
                    ]);
                }

                $active = AuthCredential::on($connection)
                    ->where('user_id', $request->userId)
                    ->where('type', 'password')
                    ->whereNull('disabled_at')
                    ->first();

                if ($active instanceof AuthCredential) {
                    return true;
                }

                $disabled = AuthCredential::on($connection)
                    ->where('user_id', $request->userId)
                    ->where('type', 'password')
                    ->whereNotNull('disabled_at')
                    ->latest('id')
                    ->first();

                if ($disabled instanceof AuthCredential) {
                    $disabled->update([
                        'secret' => Hash::make($request->password),
                        'strength' => FactorStrength::Knowledge->name,
                        'disabled_at' => null,
                    ]);

                    return true;
                }

                AuthCredential::on($connection)->create([
                    'user_id' => $request->userId,
                    'type' => 'password',
                    'secret' => Hash::make($request->password),
                    'strength' => FactorStrength::Knowledge->name,
                ]);

                return true;
            },
        );
    }

    private function isIdentifierUniqueViolation(QueryException $failure): bool
    {
        $info = $failure->errorInfo;

        return ($info[0] ?? null) === '23000'
            && str_contains($failure->getMessage(), 'auth_identifiers');
    }

    /** Persist the decoy or surface a verified contention after its bounded wait. */
    private function requestDurableDecoy(IdentifierVerificationRequest $request): void
    {
        try {
            $this->boundedLockWait->enrollment(
                max(1, $this->lockWaitSeconds),
                function () use ($request): void {
                    $this->verifier->requestDecoy($request);
                },
            );
        } catch (QueryException $failure) {
            // A verified code here can only have reached us after the scoped
            // BoundedLockWait budget. Do not turn its missing durable decoy
            // into an Accepted response. Unmeasured database failures are
            // equally loud, without being mislabeled as lock contention.
            if (! $this->isLockContention($failure)) {
                throw $failure;
            }

            throw $failure;
        }
    }

    private function isLockContention(QueryException $failure): bool
    {
        return $this->lockContention->isVerified($this->connection, $failure);
    }
}
