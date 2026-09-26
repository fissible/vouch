<?php

declare(strict_types=1);

/*
 * Prints the bucket mapping for a fixed set of scopes, in a FRESH process.
 *
 * Cross-process agreement is the only way to catch a derivation seeded per
 * process: such an implementation is perfectly stable within one request, and two
 * workers handling concurrent issuance for one identifier then take different
 * mutexes and do not serialize at all. A fork cannot show it, because a fork
 * inherits an already-initialised seed.
 *
 * No database. An earlier version of this fixture bound a real connection and
 * passed the engine's configuration in, because the comparison key was taken from
 * the database at the time; the derivation reads a canonical string and a secret
 * now, so a config repository is the whole environment it needs.
 *
 * The secret arrives in the ENVIRONMENT rather than in argv, so it is not visible
 * in `ps` to anyone else on the machine.
 *
 * Usage: VOUCH_ISSUANCE_LOCKS_SECRET=... php issuance-lock-mapping.php <package-root>
 */

require $argv[1] . '/vendor/autoload.php';

$secret = getenv('VOUCH_ISSUANCE_LOCKS_SECRET');

if (! is_string($secret) || $secret === '') {
    fwrite(STDERR, "VOUCH_ISSUANCE_LOCKS_SECRET must be set.\n");

    exit(1);
}

/*
 * A real Application rather than a bare Container: the facade root requires the
 * foundation contract, and satisfying that with a container only works until
 * static analysis looks. Nothing is bootstrapped -- no kernel, no providers -- so
 * this stays a script that derives one value.
 */
$container = new Illuminate\Foundation\Application($argv[1]);
Illuminate\Container\Container::setInstance($container);

$container->instance('config', new Illuminate\Config\Repository([
    'vouch' => ['issuance_locks' => ['secret' => $secret]],
]));

Illuminate\Support\Facades\Facade::setFacadeApplication($container);

$buckets = [];

foreach (['recovery', 'verification'] as $ceremony) {
    for ($i = 0; $i < 20; $i++) {
        $buckets[] = Fissible\Vouch\Support\IssuanceLockBucket::for(
            $ceremony,
            'email',
            sprintf('cross-process-%d@acme.example', $i),
        );
    }
}

echo json_encode($buckets, JSON_THROW_ON_ERROR), PHP_EOL;
