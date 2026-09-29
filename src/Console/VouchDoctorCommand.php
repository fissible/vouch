<?php

declare(strict_types=1);

namespace Fissible\Vouch\Console;

use Fissible\Vouch\Authorization\AssuranceRequirements;
use Fissible\Vouch\Contracts\CaptchaVerifier;
use Fissible\Vouch\Contracts\DeliveryEconomics;
use Fissible\Vouch\Contracts\OtpDelivery;
use Fissible\Vouch\Delivery\UnconfiguredCaptchaVerifier;
use Fissible\Vouch\Models\AuthIdentifier;
use Fissible\Vouch\Notifications\OtpQueueDispatcher;
use Fissible\Vouch\Notifications\UnconfiguredOtpDelivery;
use Fissible\Vouch\Sessions\SessionAssuranceRecord;
use Fissible\Vouch\Support\AttemptWindow;
use Fissible\Vouch\Support\IssuanceLockBucket;
use Fissible\Vouch\Throttle\ThrottleConfiguration;
use Fissible\Vouch\Tokens\TokenAssuranceRecord;
use Fissible\Vouch\Delivery\UnconfiguredDeliveryEconomics;
use Illuminate\Console\Command;
use Throwable;

/** Reports aggregate adoption prerequisites without inspecting any account. */
final class VouchDoctorCommand extends Command
{
    protected $signature = 'vouch:doctor {--json : Emit machine-readable aggregate JSON}';

    protected $description = 'Check Vouch adoption prerequisites.';

    /** @throws \JsonException */
    public function handle(
        OtpQueueDispatcher $dispatcher,
        ThrottleConfiguration $throttle,
        SessionAssuranceRecord $sessionAssurances,
        TokenAssuranceRecord $tokenAssurances,
    ): int {
        try {
            $totalIdentifiers = AuthIdentifier::query()->count();
            $verifiedIdentifiers = AuthIdentifier::query()->whereNotNull('verified_at')->count();
            $rows = [
                [
                    'prerequisite' => 'verified_at',
                    'status' => $totalIdentifiers > 0 && $verifiedIdentifiers === 0 ? 'missing' : 'pass',
                    'total_identifiers' => $totalIdentifiers,
                    'verified_identifiers' => $verifiedIdentifiers,
                ],
                ['prerequisite' => 'OtpDelivery', 'status' => $this->deliveryStatus()],
                ['prerequisite' => 'durable_queue', 'status' => $this->queueStatus($dispatcher)],
                ['prerequisite' => 'DeliveryEconomics', 'status' => $this->economicsStatus()],
            ];

            if ($throttle->captchaEnabled) {
                $rows[] = [
                    'prerequisite' => 'CaptchaVerifier',
                    'status' => $this->captchaStatus(),
                ];
            }

            /*
             * #82. The boot checks this command is EXEMPT from, appended here.
             *
             * VouchServiceProvider::boot() refuses to boot on each of these and lets
             * vouch:doctor through anyway, on the reasoning that the one command whose
             * job is to report a misconfiguration must not be stopped by one. Three of
             * the four had no row, so a host with a blank VOUCH_ATTEMPT_TTL, no
             * issuance-mutex secret, or a strict assurance map naming an undeclared
             * ability got a report that exited successfully and listed nothing wrong
             * while every login 500'd or every issuance refused. An exemption whose
             * premise is "they can still diagnose it" has to be matched by something
             * that diagnoses it.
             *
             * Named by the configuration key an operator has to change, because that is
             * what they will search for. CaptchaVerifier above keeps its contract name
             * because what must be configured there is a binding, not a key.
             *
             * APPENDED, not prepended: two tests in VouchDoctorCommandTest index into
             * this list at [0] and [2], so the four shipped rows keep their positions.
             *
             * Each status re-uses the predicate boot itself calls -- that is the point
             * of the shape rather than an economy. A second implementation of any of
             * them can drift from boot's, and a row that disagrees with the check it
             * describes is #82 again.
             */
            $rows[] = [
                'prerequisite' => AttemptWindow::KEY,
                'status' => $this->attemptWindowStatus(),
            ];
            $rows[] = [
                'prerequisite' => IssuanceLockBucket::SECRET_KEY,
                'status' => $this->issuanceSecretStatus(),
            ];

            /*
             * Only when the feature is on, as the CAPTCHA row is. The strict check is
             * the only one of the four boot skips entirely when a setting is off, and
             * reporting "pass" for a map nobody asked to be validated would tell an
             * operator their configuration was checked when it was not.
             */
            if (config('vouch.assurance_strict') === true) {
                $rows[] = [
                    'prerequisite' => 'vouch.declared_abilities',
                    'status' => $this->declaredAbilitiesStatus(),
                ];
            }

            $missing = count(array_filter(
                $rows,
                static fn (array $row): bool => $row['status'] === 'missing',
            ));

            $driftTables = [
                $sessionAssurances->driftCounts($this->driftBatch()),
                $tokenAssurances->driftCounts($this->driftBatch()),
            ];
            $report = [
                'missing' => $missing,
                'prerequisites' => $rows,
                'acr_drift' => [
                    'status' => array_any($driftTables, static fn (array $table): bool => $table['drifted'] > 0) ? 'drift' : 'pass',
                    'tables' => $driftTables,
                ],
            ];

            if ($this->option('json') === true) {
                $this->line(json_encode($report, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES));
            } else {
                $this->table(['Prerequisite', 'Status', 'Details'], array_map(
                    static fn (array $row): array => [
                        $row['prerequisite'],
                        $row['status'],
                        isset($row['total_identifiers'])
                            ? sprintf('%d total, %d verified', $row['total_identifiers'], $row['verified_identifiers'])
                            : '',
                    ],
                    $rows,
                ));
                $this->table(['Table', 'Checked', 'Drifted', 'Unreadable'], array_map(
                    static fn (array $table): array => [
                        $table['table'],
                        $table['checked'],
                        $table['drifted'],
                        $table['unreadable'],
                    ],
                    $driftTables,
                ));
            }

            return $missing === 0
                ? CommandExit::Success->value
                : CommandExit::Failure->value;
        } catch (Throwable $exception) {
            $this->components->error('Vouch doctor could not complete: ' . $exception->getMessage());

            // 2 is diagnostic failure here; CommandExit::DeliveryHealth uses
            // the same integer for vouch:prune's distinct domain signal.
            return 2;
        }
    }

    private function deliveryStatus(): string
    {
        return app(OtpDelivery::class) instanceof UnconfiguredOtpDelivery ? 'missing' : 'pass';
    }

    private function economicsStatus(): string
    {
        return app(DeliveryEconomics::class) instanceof UnconfiguredDeliveryEconomics ? 'missing' : 'pass';
    }

    private function captchaStatus(): string
    {
        return app(CaptchaVerifier::class) instanceof UnconfiguredCaptchaVerifier ? 'missing' : 'pass';
    }

    /*
     * The three below each answer by CALLING the check rather than restating it, so
     * the row cannot disagree with the boot condition it describes. Catching
     * Throwable rather than the declared exception type for the same reason: the
     * question is whether the check refuses, not which class it refuses with, and
     * pinning the type here would make a refactor of the refusal read as a pass.
     *
     * Locally, not through handle()'s catch: that one reports diagnostic FAILURE and
     * exits 2. A misconfiguration this command exists to name is a finding, not an
     * inability to look.
     */
    private function attemptWindowStatus(): string
    {
        try {
            AttemptWindow::seconds();

            return 'pass';
        } catch (Throwable) {
            return 'missing';
        }
    }

    private function issuanceSecretStatus(): string
    {
        try {
            IssuanceLockBucket::secret();

            return 'pass';
        } catch (Throwable) {
            return 'missing';
        }
    }

    private function declaredAbilitiesStatus(): string
    {
        try {
            app(AssuranceRequirements::class)->assertDeclared(
                AssuranceRequirements::declaredFrom(config('vouch.declared_abilities')),
            );

            return 'pass';
        } catch (Throwable) {
            return 'missing';
        }
    }

    private function queueStatus(OtpQueueDispatcher $dispatcher): string
    {
        try {
            $dispatcher->assertAsynchronous();

            return 'pass';
        } catch (Throwable) {
            return 'missing';
        }
    }

    private function driftBatch(): int
    {
        return max(1, config()->integer('vouch.doctor.drift_batch', 500));
    }
}
