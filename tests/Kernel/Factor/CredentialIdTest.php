<?php

declare(strict_types=1);

use Fissible\Vouch\Kernel\Factor\CredentialId;

/**
 * #19. The credential identity domain, asserted in the kernel because that is where it lives.
 *
 * The behavioural boundaries -- a token proof, a session proof, attempt evidence, the lock path --
 * are in tests/Database/CredentialIdentityDomainTest.php. This file exists in addition because the
 * kernel is mutation-tested on its own (`pest --mutate --class="Fissible\Vouch\Kernel" tests/Kernel`),
 * so a rule that lives in the kernel and is only exercised from a database test reads as untested
 * logic: it dropped the covered-kernel score from 97.6% to 91.7%.
 *
 * Each case below exists to kill a specific mutant rather than to restate the rule, which is why the
 * lengths and the off-by-ones are spelled out.
 */
it('accepts a canonical positive decimal id', function (string $value): void {
    CredentialId::validate($value);

    expect(true)->toBeTrue();
})->with([
    'one' => '1',
    'single digit' => '9',
    'two digits' => '10',
    'many digits' => '1234567890',
    // Nineteen characters, and the largest value every supported engine stores unchanged. Kills the
    // boundary mutants on both the length test and the string comparison.
    'the portable maximum' => '9223372036854775807',
]);

it('refuses anything that is not one', function (string $value): void {
    expect(fn () => CredentialId::validate($value))->toThrow(InvalidArgumentException::class);
})->with([
    'empty' => '',
    'zero' => '0',
    'leading zero' => '09',
    'several leading zeros' => '007',
    'non numeric' => 'cred-1',
    'decimal point' => '9.0',
    'hexadecimal' => '0x9',
    'exponent' => '9e0',
    'leading plus' => '+9',
    'negative' => '-1',
    'leading space' => ' 9',
    'trailing space' => '9 ',
    // PCRE's `$` matches before a final newline; `\z` does not. Kills the anchor mutant.
    'trailing newline' => "9\n",
    'full width digit' => "\u{FF11}",
    // Nineteen characters and one above the maximum, so only the comparison can reject it.
    'one above the portable maximum' => '9223372036854775808',
    // Twenty characters, so only the length can reject it.
    'twenty digits' => '18446744073709551616',
]);

it('names the value it refused', function (): void {
    // The refusal is a configuration-grade diagnostic: without the value, a caller with several
    // factors cannot tell which one was wrong.
    expect(fn () => CredentialId::validate('09'))
        ->toThrow(InvalidArgumentException::class, '09');
});
