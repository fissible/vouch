<?php

declare(strict_types=1);

namespace Fissible\Vouch\Credentials;

final class CredentialWriterManifest
{
    /** @return array<string, list<string>> */
    public static function classified(): array
    {
        return [
            'Attempts/DatabaseAttemptStore.php' => ['apply(): bookkeeping for AdvanceCredentialTimestep and DisableCredential; it advances or consumes a verification marker.'],
            'Enrollment/FirstCredentialEnrollment.php' => ['write(): subjectWide when reusing a disabled password row, because the secret is replaced.', 'write(): additive when it creates the first password credential for a subject.'],
            'Factors/Drivers/OtpFactor.php' => ['enroll(): additive when it reactivates an existing secretless OTP credential.', 'enroll(): additive when it creates a new OTP credential for a verified identifier.', 'revoke(): revoking because disabling the OTP factor invalidates proofs that cite it.'],
            'Factors/Drivers/PasswordFactor.php' => ['enroll(): revoking when replacement disables the old password credential.', 'enroll(): additive when it creates an ordinary new password credential.', 'revoke(): revoking because the removed password can no longer support its proofs.'],
            'Factors/Drivers/RecoveryCodeFactor.php' => ['enroll(): revoking when regeneration disables every active recovery credential.', 'enroll(): additive when first enrollment creates a recovery-code credential.', 'revoke(): revoking because disabling one recovery credential withdraws its proof.'],
            'Factors/Drivers/TotpFactor.php' => ['enroll(): revoking when replacement disables the old TOTP seed.', 'enroll(): additive when it creates a newly enrolled TOTP credential.', 'revoke(): revoking because the disabled TOTP seed can no longer support its proofs.'],
        ];
    }
}
