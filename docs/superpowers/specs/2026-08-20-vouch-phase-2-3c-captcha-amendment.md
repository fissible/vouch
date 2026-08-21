# Phase 2.3c — CAPTCHA kernel-surface amendment

**Status:** Declared 2026-08-20 alongside the first implementation slice.

2.3c adds one deliberate public-surface field to `ScreenSpec`:
`captchaRequired`, nullable because an absent value means that no shared/volume
CAPTCHA requirement was measured. The field is serialized as `null` when it is
not measured and `true` only when a shared or volume policy requires a
verification step.

This is a disclosure-surface amendment, not an incidental response field. The
API snapshot in `docs/kernel-api-surface.md` is updated and guarded by
`ApiSurfaceTest`.

## Security invariant

The field may never be derived from an identifier-specific counter, resolved
user, credential, or target. A shared-volume CAPTCHA requirement is safe only
when the shared counter advances identically for known and nonexistent
identifiers. The flow must therefore prove the coupled property: equalized
known and unknown submissions reach the same CAPTCHA threshold and expose the
same `captchaRequired` value under the same posture.

`CaptchaVerifier` remains provider-independent and fail-closed. No provider
diagnostics, token secret, account identity, or delivery target crosses the
screen or serializer boundary.
