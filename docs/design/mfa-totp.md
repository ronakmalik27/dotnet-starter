# MFA / TOTP (two-factor authentication)

Status: DESIGN (proposed). The tenth SaaS grow-into feature (multi-tenancy.md
section 21: "MFA / TOTP: an Identity add-on on the sign-in path; no tenancy
change"). Docs-first: nothing here is built until this revision is reviewed. It is a
pure Identity-module feature - MFA is a property of the global user (like the
password), enrolled per user, enforced at global login. No tenant is involved and no
tenancy code changes (a tenant REQUIRING MFA of its members is a documented
grow-into, section 10).

## 1. The decision, up front

- **TOTP (RFC 6238) as the second factor, the industry-standard authenticator-app
  method** (Google Authenticator, 1Password, Authy): a shared secret plus a 30-second
  time step yields a 6-digit code. No SMS (SIM-swap-prone, a below-par choice), no
  proprietary push. WebAuthn/passkeys are the stronger modern option and a documented
  grow-into (section 10); TOTP is the universal baseline a starter should ship.
- **Two-step login.** Password stays the first factor. After the password verifies,
  if the user has CONFIRMED MFA, login does NOT issue a session; it returns an MFA
  CHALLENGE, and a second endpoint exchanges the challenge plus a valid TOTP (or
  recovery) code for the session. A user without confirmed MFA logs in exactly as
  today (one step).
- **The secret is recoverable and encrypted at rest.** Verifying a TOTP code needs
  the raw shared secret, so (unlike a password) it cannot be hashed. It is encrypted
  with the DataProtection key ring (the `WebhookSecretProtector` pattern from
  webhooks.md section 5, purpose `identity.mfa.secret.v1`), so it is never stored in
  clear and every replica decrypts with the same persisted keys.
- **Recovery codes are the lost-authenticator escape hatch**, and they ARE hashed
  (high-entropy random, one-time), the API-key SHA-256 discipline (service-accounts.md).
- **The TOTP algorithm is pinned by the RFC's own official test vectors.** RFC 6238 is
  small and precisely specified; the implementation uses the built-in `HMACSHA1` and
  is verified against the RFC 6238 Appendix B golden vectors (the same "pin the
  algorithm with a golden test" discipline as the feature-flag bucket), so no new
  crypto dependency is taken. (A vetted library such as Otp.NET is the alternative;
  the hand-rolled+golden-vector path avoids a dependency and is correctness-verified.)

## 2. Data model (Identity)

`identity.mfa_credentials`, one per user:

| column | type | notes |
|---|---|---|
| `user_id` | uuid | PK (one MFA enrollment per user) |
| `secret_encrypted` | text not null | the TOTP shared secret, DataProtection-encrypted (never clear) |
| `confirmed_at` | timestamptz null | null = enrollment begun but not confirmed (MFA NOT enforced yet); set on the first valid code |
| `last_step` | bigint null | the last time-step a code was accepted for (replay guard, section 3) |
| `created_at` | timestamptz not null | |

`identity.mfa_recovery_codes`:

| column | type | notes |
|---|---|---|
| `id` | uuid | PK |
| `user_id` | uuid not null | |
| `code_hash` | text not null | SHA-256 hex of the code; the code itself is shown once and never stored |
| `used_at` | timestamptz null | one-time: set when consumed, a used code never works again |
| `created_at` | timestamptz not null | |

- These are global-user tables (no tenant_id, no RLS) - they sit with the other
  Identity credential tables (`users`, `auth_methods`), scoped by `user_id`, exactly
  like the password credential. MFA is not a tenant-owned concept.
- An `mfa_credentials` row with `confirmed_at = null` means enrollment is pending and
  MFA is NOT enforced at login; only `confirmed_at != null` gates login.

## 3. TOTP verification (RFC 6238)

- HMAC-SHA1 (built-in `HMACSHA1`) over the 8-byte big-endian time-step counter
  (`floor(unixSeconds / 30)`), the standard dynamic-truncation to a 31-bit integer,
  then `mod 1_000_000` for 6 digits (zero-padded left to 6). The secret is 20 random
  bytes.
- **Base32 (RFC 4648) is a hand-rolled codec too, and it is PINNED on its own.** No
  base32 helper exists in the repo, so one is written. It is the single canonical
  string form of the secret: the `otpauth://` URI carries it, the DataProtection
  protector stores `Protect(base32Secret)` (the protector takes/returns strings), and
  TOTP computation base32-DECODES it back to the 20 raw bytes for the HMAC. Pin the
  codec against the RFC 4648 section 10 test vectors (the published `""/"f"/"fo"/
  "foo"/..` -> base32 pairs), with the same rigor as the HOTP pinning - a wrong
  bit-packing or padding edge case must fail the build, not hide behind the one
  20-byte (clean multiple of 5) secret length that would mask it.
- **Skew window +/-1 step**: accept the code for the current step and the two
  adjacent steps (covers a client clock up to ~30s off). Wider windows weaken the
  factor; +/-1 is the common default.
- **Constant-time comparison.** Compare the computed code to the submitted code with
  a fixed-time comparison (`CryptographicOperations.FixedTimeEquals` over the digit
  bytes), never `==` / `string.Equals`, so a timing side-channel cannot leak
  digit-by-digit correctness.
- **Replay guard.** A TOTP code is valid for its whole ~30-90s window, so a code
  observed once could be replayed within it. On a successful verify, record the
  accepted time-step in `last_step` and REJECT any code whose step is `<= last_step`.
  So each code (and each step) is single-use even inside its validity window. (Traced
  against the skew window: accepted steps are monotonically non-decreasing across
  genuine logins, so this never wrongly rejects the next legitimate step, only a true
  replay.)
- **Unprotect failure is handled, not fatal.** Verifying needs the raw secret, so a
  lost / rotated-away DataProtection key ring makes a TOTP code unverifiable. Wrap
  `Unprotect` in a distinct exception (the `WebhookSecretUnprotectException` pattern)
  and return a controlled error, NOT an unhandled 500. The recovery-code path
  (SHA-256 hashed, key-ring-independent, section 6) is the documented fallback for a
  user whose TOTP cannot be decrypted.
- **Golden-vector test (the load-bearing correctness gate).** RFC 6238 Appendix B
  publishes its vectors as 8-DIGIT codes; this feature uses 6 digits, and the correct
  6-digit value is the LAST six of the 8-digit value (`fullCode mod 1_000_000`), NOT
  the first six (real authenticators truncate to the low-order digits). State this
  derivation in the test and assert the adapted 6-digit expected values for the
  SHA-1 vectors directly (T=59 -> `287082`, T=1111111109 -> `081804`, T=1111111111
  -> `050471`, derived as the low six digits of the published `94287082` /
  `07081804` / `14050471`), so a byte-order or truncation bug fails the build.

## 4. Enrollment

**Enabling MFA is a step-up operation, security-equivalent to changing a password.**
Both enroll and confirm require a FRESH credential proof (the current password),
NOT just an authenticated session - the same bar `/disable` (section 7) already
sets for turning MFA OFF. Without this, a briefly-hijacked access token (a stolen
15-minute token, an XSS elsewhere) makes two API calls to enroll an
ATTACKER-controlled secret, receive the recovery codes, and permanently take over:
the legitimate owner then hits the MFA challenge on every login holding neither the
authenticator nor a recovery code. Requiring the current password means an attacker
with only a session cannot enroll. (A passwordless / Google-only account, which has
no password to re-enter, must set a password OR re-prove via a fresh OIDC sign-in
before enrolling - a documented step-up path, section 10.)

- `POST /api/v1/auth/mfa/enroll` (authenticated + current password): generate a
  20-byte secret, store it ENCRYPTED with `confirmed_at = null` (replacing any prior
  unconfirmed row), and return the otpauth URI
  `otpauth://totp/{issuer}:{email}?secret={base32}&issuer={issuer}` (percent-encode
  the issuer and email label segments with `Uri.EscapeDataString`, so an email or
  issuer with reserved URI characters cannot produce a malformed URI) and the base32
  secret (for manual entry) - shown ONCE, so the client can render a QR. This does NOT
  yet enable MFA.
- `POST /api/v1/auth/mfa/confirm` (authenticated + current password, body: a code
  from the authenticator): verify the code against the pending secret; on success set
  `confirmed_at`, GENERATE the recovery codes (section 6, shown ONCE in the response,
  stored hashed), and MFA is now enforced at login. A wrong code returns a validation
  error and does not confirm. Confirming proves the user's authenticator actually
  works before they are locked into needing it.
- Re-enroll (enroll again while already confirmed) begins a fresh pending secret;
  MFA stays on the OLD secret until a new confirm succeeds, so a half-finished
  re-enroll never locks the user out.

## 5. Login step-up

- `LoginHandler`, after the password verifies (and the lockout/reset logic of
  role-templates-and-policy-defaults.md section 4), checks for a CONFIRMED
  `mfa_credentials` row. If none, it issues the session exactly as today. If present,
  it returns an MFA challenge instead of the session. `Result<IssuedTokens>` cannot
  carry a third outcome, so the handler's return becomes `Result<LoginOutcome>` where
  `LoginOutcome` is a discriminated `Tokens(IssuedTokens)` | `MfaChallenge(string
  Token, int ExpiresInSeconds)` (not a dual-nullable hack). The endpoint maps
  `Tokens` -> the normal token response and `MfaChallenge` -> `{ mfaRequired: true,
  challenge, expiresIn }`.
- **The challenge token** is a signed JWT with a DISTINCT audience (`mfa-challenge`,
  NOT `StarterAuth.Audience`), `sub = userId`, a ~5-minute expiry, and no `sid`.
  Because the app's only registered JWT bearer scheme validates
  `ValidAudience = StarterAuth.Audience`, a `mfa-challenge`-audience token is rejected
  outright by normal access-token authentication - it can NEVER be used as an access
  token (verified: `StarterJwtAuthentication` sets `ValidateAudience = true`). The
  mint and the validate are explicit new paths, since `AccessTokenIssuer` hardcodes
  the access audience: a small dedicated challenge issuer mints it, and the mfa-verify
  endpoint validates it by calling `JsonWebTokenHandler.ValidateTokenAsync` with its
  own `TokenValidationParameters` (`ValidAudience = "mfa-challenge"`, same signing
  key/issuer) INSIDE the handler - NOT via the `[Authorize]` pipeline (which would 401
  on the audience before the handler runs). It proves "first factor passed"; alone it
  is useless (it still needs a code).
- `POST /api/v1/auth/mfa/verify` (body: the challenge token + a `code`): validate the
  challenge (audience, expiry, signature), then accept EITHER a TOTP code (section 3,
  with the replay guard) OR a recovery code (section 6). On success, issue the real
  session (`SessionIssuer.IssueAsync`, tenant-less like a normal login) - the caller
  selects a tenant next, unchanged.
- **Brute-force throttling of the verify endpoint is mandatory (a 6-digit code is
  only 10^6, and a recovery code space is finite).** A challenge token holder must not
  get unlimited guesses. Cap failed verifies PER USER using the SAME lockout mechanism
  the password path uses (`auth_methods`-style failed-attempt count + lock, or a
  dedicated `mfa_credentials.failed_attempts` + `locked_until`): after N failed codes
  the MFA step locks for the lockout duration, and a fresh challenge does not reset
  the count. Without this, MFA adds little over a stolen password. Reset the count on
  a successful verify. The generic-answer / timing discipline from the password path
  applies here too.

## 6. Recovery codes

- Generated at confirm (and regenerable via `POST /api/v1/auth/mfa/recovery-codes`,
  authenticated + a fresh TOTP code, which REPLACES all prior codes): 10 codes, each
  at least 16 base32 chars (~80 bits), shown ONCE, stored as SHA-256 hex. The 80-bit
  floor is deliberate: unlike the other SHA-256-hashed secrets in this codebase (API
  keys, one-time tokens - all 256-bit, "no stretching needed"), a recovery code is
  human-typed, so it cannot be 256-bit; but a ~50-bit code (10 base32 chars) is
  OFFLINE-brute-forceable across the whole space on commodity GPUs if the
  `mfa_recovery_codes` table ever leaks, whereas ~80 bits keeps a leaked-table attack
  infeasible. Format in groups for legibility (e.g. `xxxx-xxxx-xxxx-xxxx`, strip
  separators on submit).
- A recovery code is accepted at mfa-verify in place of a TOTP code; consume it with
  a SINGLE atomic conditional update - `update identity.mfa_recovery_codes set
  used_at = @now where user_id = @u and code_hash = @hash and used_at is null`,
  accepting only when rows-affected == 1 (the `ExecuteUpdateAsync` idiom the password
  lockout uses). A read-then-write would let two concurrent submissions of the same
  code both pass the check and mint two sessions from one one-time code. Constant-time
  compare is not required for a high-entropy hash lookup (the API-key-resolver
  precedent).
- Regenerating invalidates all outstanding codes (delete + reissue), so a user who
  suspects a leaked list can rotate.

## 7. Disable MFA

- `POST /api/v1/auth/mfa/disable` (authenticated + a fresh TOTP or recovery code):
  re-verifying the second factor proves it is really the enrolled user (not a hijacked
  session) turning MFA off. On success, delete the `mfa_credentials` row and all
  recovery codes. Login reverts to one step.
- A super-admin "reset a locked-out user's MFA" is a documented grow-into (section
  10) - it is an operator recovery path, deliberately not built into the self-serve
  surface.

## 8. Events and audit

- `identity.mfa.enabled` (on confirm) and `identity.mfa.disabled` (on disable) are
  GLOBAL identity events, the same class as `identity.password.changed`: they carry no
  tenant, so they are NOT on the tenant-scoped deliverable catalogue and NOT in the
  tenant audit log. The existing `IdentityNotificationsConsumer` must be EXPLICITLY
  extended (its `EventTypes` is a fixed array and its `Compose` is a switch with no
  `mfa.*` case today) - add the two event types + two `Compose` cases with real copy
  ("MFA was enabled / disabled on your account", the security-notice pattern); it does
  not pick them up implicitly. They are added to the `AuditLogTests` NotAudited set
  like the other
  `identity.*` events.
- Recovery-code use and MFA-verify failures are not domain events (high-volume / login
  path); the `last_step`, `used_at`, and lock state are the durable record.

## 9. Deletability

Additive and removable: drop `identity.mfa_credentials` + `identity.mfa_recovery_codes`
and their migration, the TOTP helper, the enroll/confirm/verify/disable/recovery
endpoints, and the `MfaRequired` branch in `LoginHandler` (login reverts to the
single-step flow). No other module references MFA; the DataProtection key ring and
the lockout mechanism are shared and untouched.

## 10. Deferred (documented grow-into, not built)

- WebAuthn / passkeys (phishing-resistant hardware/platform authenticators) as a
  stronger second (or first) factor.
- A tenant POLICY requiring MFA of its members (enforced at the tid-token mint or a
  per-request gate for that tenant) - the first place MFA would touch tenancy, hence
  deferred (the committed scope is "no tenancy change").
- A super-admin MFA reset for a user who has lost both authenticator and recovery
  codes (an audited operator recovery path). Deferred deliberately, and the risk it
  would otherwise carry is bounded by two controls this increment DOES ship: the
  step-up on enroll/confirm (section 4) means an attacker with only a session cannot
  turn MFA on against a victim (no attacker-driven lockout), and the recovery codes
  (section 6, shown at confirm) are the user's own self-recovery path. So the
  remaining exposure is narrowly "a user who both enabled MFA and lost their
  authenticator AND every recovery code" - a support-ticket case, not a takeover
  vector; an operator reset (delete the user's `mfa_credentials` + recovery codes,
  audited) is the clean grow-into for it.
- "Remember this device" (a trusted-device token that skips the second factor for a
  bounded window on a known device).
- SMS/email OTP as an additional (weaker) method, behind the same challenge flow.

## 11. Tests

- **TOTP correctness**: the RFC 6238 Appendix B golden vectors pass (the load-bearing
  algorithm gate); a code from the current step verifies, a code from two steps away
  fails (outside the +/-1 window); the replay guard rejects a code whose step `<=
  last_step`.
- **Enrollment**: enroll returns an otpauth URI + secret and does NOT enforce MFA;
  confirm with a valid code enables MFA and returns 10 recovery codes; confirm with a
  wrong code does not enable; a pending re-enroll does not disturb an active secret.
- **Login step-up**: a confirmed-MFA user's password login returns `MfaRequired` + a
  challenge (no session tokens); mfa-verify with a valid TOTP issues the session;
  mfa-verify with a recovery code issues the session and burns the code (reuse fails);
  the challenge token is rejected by normal access-token authentication (wrong
  audience); a non-MFA user logs in in one step unchanged.
- **Brute-force**: N wrong codes against the verify endpoint lock the MFA step for the
  user (a subsequent CORRECT code fails while locked); a fresh challenge does not
  reset the count; a successful verify resets it.
- **Disable**: disable requires a fresh valid code; after disable, login is one step
  and the recovery codes are gone.
