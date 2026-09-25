<?php

declare(strict_types=1);

/*
 * Prints the bucket mapping for a fixed set of scopes, in a FRESH process.
 *
 * Cross-process agreement is the only way to catch a derivation seeded per
 * process: such an implementation is perfectly stable within one request, and
 * two workers handling concurrent issuance for the same identifier then take
 * different mutexes and do not serialize at all. A fork cannot show it, since a
 * fork inherits an already-initialised seed.
 *
 * A real connection is bound, because the comparison key now comes FROM the
 * database -- the earlier version of this fixture bound only a config
 * repository and therefore failed a correct implementation outright. The
 * connection configuration arrives as JSON from the caller, so this fixture
 * points at whichever engine the suite is running against rather than assuming
 * SQLite.
 *
 * Usage: php issuance-lock-mapping.php <package-root> <secret> <connection-json>
 */

require $argv[1] . '/vendor/autoload.php';

/*
 * A real Application rather than a bare Container: DatabaseManager and the
 * facade root both require the foundation contract, and satisfying them with a
 * container only works until static analysis looks. Nothing is bootstrapped --
 * no kernel, no providers -- so this stays a script that derives one value.
 */
$container = new Illuminate\Foundation\Application($argv[1]);
Illuminate\Container\Container::setInstance($container);

/** @var array<string, mixed> $connection */
$connection = json_decode($argv[3], true, 512, JSON_THROW_ON_ERROR);

$config = new Illuminate\Config\Repository([
    'app' => ['key' => $argv[2]],
    'vouch' => ['issuance_locks' => ['secret' => $argv[2]]],
    'database' => [
        'default' => 'probe',
        'connections' => ['probe' => $connection],
    ],
]);

$container->instance('config', $config);

$manager = new Illuminate\Database\DatabaseManager(
    $container,
    new Illuminate\Database\Connectors\ConnectionFactory($container),
);

$container->instance('db', $manager);
Illuminate\Database\Eloquent\Model::setConnectionResolver($manager);
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
