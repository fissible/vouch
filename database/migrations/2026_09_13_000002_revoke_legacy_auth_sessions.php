<?php

declare(strict_types=1);

use Fissible\Vouch\Sessions\RevokedReason;
use Fissible\Vouch\Support\DatabaseTime;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;

return new class extends Migration
{
    public function up(): void
    {
        $connection = DB::connection($this->getConnection());
        $time = new DatabaseTime($connection);

        // These sessions predate the ownership marker. Retain their bindings
        // so the middleware can refuse them even without a marker. Hosts must
        // also flush sessions: bindings already lost to rebinding are unknown.
        $connection->table('auth_sessions')->whereNull('revoked_at')->update([
            'revoked_at' => $time->now(),
            'revoked_reason' => RevokedReason::Superseded->value,
            'updated_at' => $time->now(),
        ]);
    }

    public function down(): void
    {
        // Rolling back code must not restore sessions revoked during upgrade.
    }
};
