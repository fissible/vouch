<?php

declare(strict_types=1);

namespace Fissible\Vouch\Contracts;

/** Optional capability for issuers that can safely report live token keys. */
interface ReportsTokenExistence
{
    /**
     * @param list<string> $tokenKeys
     * @return list<string>
     */
    public function existingTokenKeys(array $tokenKeys): array;
}
