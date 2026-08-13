<?php

declare(strict_types=1);

namespace Fissible\Vouch\Factors;

use Fissible\Vouch\Contracts\Factor;
use LogicException;

/**
 * Resolves an auth_credentials.type to the driver that owns it.
 *
 * Registration is write-once. Silent replacement would let a host swap the
 * recovery-code driver — the one carrying FactorStrength::Recovery, which is
 * what keeps a recovery code from satisfying a policy — for a permissive one,
 * simply by registering after vouch does.
 */
final class FactorRegistry
{
    /** @var array<string, Factor> */
    private array $factors = [];

    public function register(Factor $factor): void
    {
        $id = $factor->id();

        if (isset($this->factors[$id])) {
            throw new LogicException(sprintf(
                'A factor driver is already registered for "%s" (%s). Registration is '
                . 'write-once: replacing a driver silently would let a permissive '
                . 'implementation displace a restrictive one.',
                $id,
                $this->factors[$id]::class,
            ));
        }

        $this->factors[$id] = $factor;
    }

    public function has(string $id): bool
    {
        return isset($this->factors[$id]);
    }

    /**
     * @throws UnknownFactor
     */
    public function get(string $id): Factor
    {
        return $this->factors[$id] ?? throw UnknownFactor::for($id, array_keys($this->factors));
    }

    /**
     * @return list<Factor>
     */
    public function all(): array
    {
        return array_values($this->factors);
    }
}
