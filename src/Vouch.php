<?php

declare(strict_types=1);

namespace Fissible\Vouch;

use Fissible\Vouch\Kernel\Policy\PolicyParser;
use Fissible\Vouch\Kernel\Satisfiability\SatisfiabilityEvaluator;
use Fissible\Vouch\Assurance\AssuranceEvidence;
use Fissible\Vouch\Models\AuthCredential;
use Fissible\Vouch\Models\AuthPolicy;
use Fissible\Vouch\Models\AuthSession;
use Fissible\Vouch\Http\IntendedDestination;
use Fissible\Vouch\Sessions\BindingDomain;
use Fissible\Vouch\Sessions\SessionBinding;
use Fissible\Vouch\Sessions\SessionEvidence;
use Fissible\Vouch\Tokens\ActorKind;
use Fissible\Vouch\Tokens\CredentialLockManager;
use Fissible\Vouch\Tokens\IssuedToken;
use Fissible\Vouch\Tokens\IssuanceRefused;
use Fissible\Vouch\Tokens\SubjectKey;
use Fissible\Vouch\Tokens\TokenAssuranceRecord;
use Fissible\Vouch\Tokens\TokenGrant;
use Illuminate\Database\ConnectionInterface;
use Illuminate\Database\DatabaseManager;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use RuntimeException;

/**
 * The imperative entry point for demanding assurance (spec §7.5).
 *
 * `RequireAssurance` covers routes declaratively. This covers the cases that
 * are not a route boundary — a controller deciding mid-action that the next
 * step needs a stronger factor.
 *
 * Both paths store the return target the same way and fail closed the same way,
 * because two ways of starting a step-up would be two places for the
 * open-redirect rules to drift.
 */
final class Vouch
{
    /**
     * Mint a human token from the currently authenticated, live Vouch session.
     * The caller owns the transaction and must not disclose plaintext before it
     * commits.
     *
     * @throws IssuanceRefused
     */
    public static function issueToken(TokenGrant $grant, ?ConnectionInterface $connection = null): IssuedToken
    {
        /** @var DatabaseManager $database */
        $database = app('db');
        $connection ??= $database->connection();

        if ($connection->transactionLevel() < 1) {
            throw new IssuanceRefused('Token issuance requires an active caller transaction.');
        }

        if ($grant->actor !== ActorKind::Human) {
            throw new IssuanceRefused('Machine-token issuance is unavailable.');
        }

        $principal = auth()->user();
        if (! $principal instanceof Model || $principal->getKey() === null) {
            throw new IssuanceRefused('Token issuance requires live host authentication.');
        }

        $hostSessionId = session()->getId();
        if ($hostSessionId === '') {
            throw new IssuanceRefused('Token issuance requires a live host session.');
        }

        $principalSubject = SubjectKey::of($principal->getMorphClass(), $principal->getKey());
        $evidence = self::validatedSessionEvidence($connection, $hostSessionId, $principalSubject, $grant);

        $credentialIds = CredentialLockManager::canonicalCredentialIds(array_map(
            static fn ($factor): string => $factor->credentialId,
            $evidence->factors,
        ));

        app(CredentialLockManager::class)->acquire($connection, $grant->subject, $credentialIds);

        /*
         * Preserve the issuance protocol's anchor -> credential order, then
         * lock the exact session selected by session_binding before reading its
         * proof. Session-revocation paths only lock/update auth_sessions rows and do
         * not subsequently acquire subject or credential locks, so this adds
         * no reverse lock edge (and therefore no deadlock cycle).
         *
         * The first validation is advisory: a session can be revoked after it
         * and before lock acquisition. This locked validation is durable until
         * the caller's transaction commits.
         */
        $evidence = self::validatedSessionEvidence(
            $connection,
            $hostSessionId,
            $principalSubject,
            $grant,
            lockForUpdate: true,
        );
        $revalidatedCredentialIds = CredentialLockManager::canonicalCredentialIds(array_map(
            static fn ($factor): string => $factor->credentialId,
            $evidence->factors,
        ));
        if ($revalidatedCredentialIds !== $credentialIds) {
            throw new IssuanceRefused('The session proof changed while token issuance was acquiring locks.');
        }

        foreach ($credentialIds as $credentialId) {
            if ($connection->table((new AuthCredential())->getTable())
                ->where('id', $credentialId)->whereNull('disabled_at')->doesntExist()) {
                throw new IssuanceRefused('A credential in the session proof is no longer live.');
            }
        }

        /** @var \Fissible\Vouch\Contracts\TokenIssuer $issuer */
        $issuer = app(\Fissible\Vouch\Contracts\TokenIssuer::class);
        if (! $issuer->supportsTransactionalIssuance()) {
            throw new IssuanceRefused('The configured token issuer cannot enlist in this transaction.');
        }

        $issued = $issuer->issue($connection, $grant);
        app(TokenAssuranceRecord::class)->store(
            $issued->issuerKey,
            $issued->tokenKey,
            $grant->subject,
            $grant->tenantId,
            $grant->actor,
            $evidence->factors,
            $connection,
        );

        return $issued;
    }

    /**
     * Read and validate the currently bound session on the issuing connection.
     *
     * @throws IssuanceRefused
     */
    private static function validatedSessionEvidence(
        ConnectionInterface $connection,
        string $hostSessionId,
        SubjectKey $principalSubject,
        TokenGrant $grant,
        bool $lockForUpdate = false,
    ): AssuranceEvidence {
        $sessionQuery = $connection->table((new AuthSession())->getTable())
            ->where('session_binding', SessionBinding::for($hostSessionId, BindingDomain::Session));
        if ($lockForUpdate) {
            $sessionQuery->lockForUpdate();
        }
        $sessionRow = $sessionQuery->first();
        $session = $sessionRow === null ? null : (new AuthSession())->newFromBuilder(get_object_vars($sessionRow));

        $sessionSubject = $session instanceof AuthSession
            ? SubjectKey::of($principalSubject->provider, $session->user_id)
            : null;
        if ($sessionSubject === null || ! $sessionSubject->equals($principalSubject)) {
            throw new IssuanceRefused('Token issuance requires the authenticated host session.');
        }

        $evidence = SessionEvidence::read($session)->evidence;
        if ($evidence === null) {
            throw new IssuanceRefused('The authenticated session has no usable assurance proof.');
        }

        if (! $evidence->subject->equals($grant->subject) || ! $principalSubject->equals($grant->subject)) {
            throw new IssuanceRefused('The token grant subject does not match the authenticated session.');
        }

        if ($evidence->tenantId !== $grant->tenantId) {
            throw new IssuanceRefused('The token grant tenant does not match the authenticated session.');
        }

        $policy = AuthPolicy::query()->where('scope', 'token_issue')
            ->where('tenant_id', $evidence->tenantId)
            ->first();
        if (! $policy instanceof AuthPolicy || ! (new SatisfiabilityEvaluator())
            ->evaluate((new PolicyParser())->parse($policy->document), $evidence->factors)->satisfied) {
            throw new IssuanceRefused('The session proof does not satisfy token issuance policy.');
        }

        return $evidence;
    }

    /**
     * Send the caller to the step-up presentation, remembering where they were.
     *
     * @throws RuntimeException when no presentation URL is configured.
     */
    public static function stepUp(string $level, ?Request $request = null, ?string $intended = null): RedirectResponse
    {
        $request ??= request();
        $presentation = config('vouch.step_up.presentation_url');

        /*
         * FAIL CLOSED, identically to RequireAssurance. 2.3 ships no routeable
         * step-up page, so there is nowhere safe to guess: a browser sent to the
         * JSON endpoint issues a GET and receives 405.
         */
        if (! is_string($presentation) || $presentation === '') {
            throw new RuntimeException(
                'Vouch::stepUp(' . $level . ') requires vouch.step_up.presentation_url to be '
                . 'configured. 2.3 ships no routeable step-up page; Phase 3 supplies the '
                . 'standard adapter. Refusing rather than redirecting to an endpoint that '
                . 'only answers POST.',
            );
        }

        // Never a client-supplied return_to: that is an open-redirect primitive.
        (new IntendedDestination($request->session()))->remember($intended ?? $request->getRequestUri());

        return redirect()->to($presentation);
    }
}
