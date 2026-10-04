<?php

declare(strict_types=1);

namespace Fissible\Vouch\Support;

use Illuminate\Database\Connection;
use RuntimeException;
use stdClass;

/**
 * Move the package's dates past MySQL's 2038 ceiling without moving an instant.
 *
 * Ownership is the literal auth_ namespace, including the connection's table
 * prefix. Discovering its TIMESTAMP columns covers later tables too; a frozen
 * list of today's 83 columns would silently miss the next one. Sanctum's table
 * belongs to the host and is deliberately outside that namespace.
 */
final readonly class DateColumnsUpgrade
{
    public function __construct(private Connection $connection) {}

    public function apply(): void
    {
        $this->requireUtc();

        // An explicit escape character also escapes a host prefix containing %
        // or _. Bare auth_% matched authentication_events in the review probe.
        $pattern = strtr($this->connection->getTablePrefix() . 'auth_', [
            '!' => '!!', '%' => '!%', '_' => '!_',
        ]) . '%';

        // MySQL 8.4 returns unaliased information_schema fields as UPPERCASE
        // keys. Alias every selected field to keep the metadata row shape stable.
        $rows = $this->connection->select(
            'select table_name as table_name, column_name as column_name,'
            . ' cast(datetime_precision as char) as precision_digits, is_nullable as is_nullable,'
            . ' column_default as column_default, extra as extra, column_comment as column_comment'
            . ' from information_schema.columns'
            . " where table_schema = database() and table_name like ? escape '!'"
            . " and data_type = 'timestamp' order by table_name, ordinal_position",
            [$pattern],
        );

        $tables = [];

        foreach ($rows as $row) {
            if (! $row instanceof stdClass) {
                throw new RuntimeException('Vouch could not read the MySQL date column metadata.');
            }

            $table = $this->text($row, 'table_name');
            $precision = $this->text($row, 'precision_digits');
            $nullable = $this->text($row, 'is_nullable');

            if (! in_array($precision, ['0', '1', '2', '3', '4', '5', '6'], true)
                || ! in_array($nullable, ['YES', 'NO'], true)) {
                throw new RuntimeException('Vouch could not interpret the MySQL date column definition.');
            }

            $definition = 'modify ' . $this->quoteIdentifier($this->text($row, 'column_name'))
                . ' datetime(' . $precision . ') ' . ($nullable === 'YES' ? 'null' : 'not null');

            // MODIFY replaces the definition. Retain host-added defaults,
            // automatic updates and comments as well as precision/nullability.
            $extra = $this->text($row, 'extra');
            $default = $row->column_default;

            if (is_string($default)) {
                $definition .= ' default ' . (str_contains($extra, 'DEFAULT_GENERATED')
                    ? $default : $this->quoteLiteral($default));
            } elseif ($default !== null) {
                throw new RuntimeException('Vouch could not interpret the MySQL date column default.');
            }

            $definition .= ' ' . trim(str_replace('DEFAULT_GENERATED', '', $extra));
            $definition .= ' comment ' . $this->quoteLiteral($this->text($row, 'column_comment'));
            $tables[$table][] = $definition;
        }

        // Type changes require COPY. One ALTER per table pays for one rebuild,
        // not one per column. Completed tables remain converted after a later
        // failure; discovering only TIMESTAMP columns makes a retry resumable.
        foreach ($tables as $table => $definitions) {
            $this->connection->statement(
                'alter table ' . $this->quoteIdentifier($table) . ' '
                . implode(', ', $definitions) . ', algorithm=copy',
            );
        }
    }

    private function requireUtc(): void
    {
        $row = $this->connection->selectOne(
            'select @@session.time_zone as session_zone, @@system_time_zone as system_zone',
        );

        if ($row instanceof stdClass) {
            $zone = $this->text($row, 'session_zone');

            if ($zone === 'SYSTEM') {
                $zone = $this->text($row, 'system_zone');
            }

            // A zero offset NOW does not establish UTC: a named zone can fold
            // two autumn instants into one literal. The measured Berlin pair
            // did exactly that. Accept only explicit UTC or a UTC system zone.
            if (in_array($zone, ['+00:00', 'UTC', 'Etc/UTC'], true)) {
                return;
            }
        }

        // Check before any DDL, including on a fresh installation. Silently
        // forcing UTC only here would leave runtime reads on the old zone:
        // on a +02:00 host existing windows would be read two hours EARLIER.
        throw new RuntimeException(
            "Vouch requires a UTC MySQL connection before converting date columns. Set 'timezone' => '+00:00' "
            . 'on the Laravel database connection used by both migrations and runtime workers, reconnect, '
            . 'and rerun the migration with traffic paused; see docs/operations.md.',
        );
    }

    private function text(stdClass $row, string $field): string
    {
        $value = $row->{$field} ?? null;

        if (! is_string($value)) {
            throw new RuntimeException('Vouch could not read MySQL date metadata field ' . $field . '.');
        }

        return $value;
    }

    private function quoteIdentifier(string $name): string
    {
        return '`' . str_replace('`', '``', $name) . '`';
    }

    private function quoteLiteral(string $value): string
    {
        $quoted = $this->connection->getPdo()->quote($value);

        if ($quoted === false) {
            throw new RuntimeException('Vouch could not quote a MySQL date column attribute.');
        }

        return $quoted;
    }
}
