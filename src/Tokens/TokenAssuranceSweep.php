<?php

declare(strict_types=1);

namespace Fissible\Vouch\Tokens;

use Fissible\Vouch\Contracts\ReportsTokenExistence;
use Fissible\Vouch\Contracts\TokenIssuer;
use Illuminate\Database\ConnectionInterface;
use LogicException;
use Throwable;

/** Reclaims assurance history only after its issuer confirms the token is absent. */
final readonly class TokenAssuranceSweep
{
    public function __construct(
        private ConnectionInterface $connection,
        private TokenIssuerRegistry $issuers,
        private TokenAssuranceRecord $records,
        private int $batchSize = 100,
    ) {
        if ($this->batchSize < 1) {
            throw new \InvalidArgumentException('Token assurance sweep batch size must be at least 1.');
        }
    }

    public function sweep(): TokenAssuranceSweepResult
    {
        if ($this->connection->transactionLevel() > 0) {
            throw new LogicException('Token assurance sweep cannot run inside an active transaction.');
        }

        $keysByIssuer = $this->records->tokenKeysByIssuer();

        $reclaimed = 0;
        $retained = 0;
        $unsupported = 0;
        $errored = 0;
        $errors = [];
        $unsupportedIssuers = [];

        foreach ($keysByIssuer as $issuerKey => $tokenKeys) {
            $issuer = $this->issuerFor($issuerKey);

            if (! $issuer instanceof ReportsTokenExistence) {
                $unsupported += count($tokenKeys);
                $unsupportedIssuers[] = $issuerKey;

                continue;
            }

            $existing = [];

            try {
                foreach (array_chunk($tokenKeys, $this->batchSize) as $batch) {
                    $asked = array_fill_keys($batch, true);

                    foreach ($issuer->existingTokenKeys($batch) as $tokenKey) {
                        if (isset($asked[$tokenKey])) {
                            $existing[$tokenKey] = true;
                        }
                    }
                }
            } catch (Throwable $exception) {
                // Every key for this issuer is left in place. Count the held
                // records so all four outcome counts reconcile to the sweep's
                // input, while the error text identifies the failed issuer.
                $errored += count($tokenKeys);
                $errors[] = sprintf('%s: %s', $issuerKey, $exception->getMessage());

                continue;
            }

            $retained += count($existing);
            $absent = array_values(array_filter(
                $tokenKeys,
                static fn (string $tokenKey): bool => ! isset($existing[$tokenKey]),
            ));

            if ($absent === []) {
                continue;
            }

            $reclaimed += $this->records->forgetMany($issuerKey, $absent);
        }

        return new TokenAssuranceSweepResult(
            $reclaimed,
            $retained,
            $unsupported,
            $errored,
            $errors,
            $unsupportedIssuers,
        );
    }

    private function issuerFor(string $issuerKey): ?TokenIssuer
    {
        foreach ($this->issuers->issuers() as $issuer) {
            if ($issuer->issuerKey() === $issuerKey) {
                return $issuer;
            }
        }

        return null;
    }
}
