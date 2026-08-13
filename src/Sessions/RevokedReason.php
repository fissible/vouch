<?php

declare(strict_types=1);

namespace Fissible\Vouch\Sessions;

/**
 * Why a session was revoked.
 *
 * A closed set rather than free text: this value reaches user-facing sign-out
 * messaging, so free text would be an injection and disclosure surface on a
 * security-relevant path. A closed set also keeps revocations aggregatable in
 * audit, which is the point of recording them.
 *
 * There is no separate `destroyed_at`: logout, grace expiry, credential change,
 * and admin action are all revocations differing only in cause, which is what
 * this enum records.
 */
enum RevokedReason: string
{
    case Logout = 'logout';
    case GraceExpired = 'grace_expired';
    case CredentialChanged = 'credential_changed';
    case PasswordChanged = 'password_changed';
    case AdminRevoked = 'admin_revoked';
    case Superseded = 'superseded';
}
