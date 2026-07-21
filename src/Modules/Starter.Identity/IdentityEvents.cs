using System.Text.Json;
using Starter.Platform.Events;
using Starter.SharedKernel;

namespace Starter.Identity;

/// <summary>
/// The identity rows of the event catalogue this story
/// produces. Payloads follow the privacy rule: ids and coarse
/// metadata only - never the email address or any credential material.
/// </summary>
internal static class IdentityEvents
{
    private const string Module = "identity";

    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    /// <summary>
    /// identity.user.registered: account created. Method is
    /// the auth_methods kind that created it (password / google).
    /// </summary>
    public static DomainEventRecord UserRegistered(Guid userId, string method, DateTimeOffset now) => new()
    {
        Id = Ids.NewId(now),
        OccurredAt = now,
        Module = Module,
        EventType = "identity.user.registered",
        EntityId = userId,
        ActorUserId = userId,
        Payload = JsonSerializer.Serialize(new { method }, Json),
    };

    /// <summary>
    /// identity.auth_method.linked: a new credential attached
    /// to an EXISTING account (account-linking; a brand-new
    /// account emits user.registered instead). passwordDisabled marks the
    /// unverified-claim path, where the pre-existing password credential
    /// is distrusted until reset - the N:security notice's cue.
    /// </summary>
    public static DomainEventRecord AuthMethodLinked(
        Guid userId,
        string kind,
        bool passwordDisabled,
        DateTimeOffset now) => new()
        {
            Id = Ids.NewId(now),
            OccurredAt = now,
            Module = Module,
            EventType = "identity.auth_method.linked",
            EntityId = userId,
            ActorUserId = userId,
            Payload = JsonSerializer.Serialize(new { kind, passwordDisabled }, Json),
        };

    /// <summary>
    /// identity.password.changed: self-service credential
    /// change; one slice is the passwordless account setting its first
    /// password (dual-method). N:security notifies.
    /// </summary>
    public static DomainEventRecord PasswordChanged(Guid userId, DateTimeOffset now) => new()
    {
        Id = Ids.NewId(now),
        OccurredAt = now,
        Module = Module,
        EventType = "identity.password.changed",
        EntityId = userId,
        ActorUserId = userId,
        Payload = "{}",
    };

    /// <summary>
    /// identity.registration.reattempted: someone submitted a
    /// registration for an email that already has an account.
    /// The responder returned the same success as a fresh registration;
    /// this event carries the "was this you?" notice to the notifications
    /// consumer. Actor is null: the submitter is unauthenticated and
    /// unproven.
    /// </summary>
    public static DomainEventRecord RegistrationReattempted(Guid existingUserId, DateTimeOffset now) => new()
    {
        Id = Ids.NewId(now),
        OccurredAt = now,
        Module = Module,
        EventType = "identity.registration.reattempted",
        EntityId = existingUserId,
        ActorUserId = null,
        Payload = JsonSerializer.Serialize(new { method = "password" }, Json),
    };

    /// <summary>
    /// identity.user.verified: the email address is proven.
    /// The verify_email token flow emits this for password accounts;
    /// Google sign-in emits it when claiming or creating a
    /// verified identity. No payload by catalogue design.
    /// </summary>
    public static DomainEventRecord UserVerified(Guid userId, DateTimeOffset now) => new()
    {
        Id = Ids.NewId(now),
        OccurredAt = now,
        Module = Module,
        EventType = "identity.user.verified",
        EntityId = userId,
        ActorUserId = userId,
        Payload = JsonSerializer.Serialize(new { }, Json),
    };

    /// <summary>
    /// identity.session.created: login. The payload carries the coarse
    /// device label only. The client IP is deliberately NOT on the spine:
    /// domain_events is append-only and retained forever with no per-row
    /// erasure path, so an IP - personal data under GDPR - would become
    /// undeletable PII. The IP still lives on the mutable sessions row (set
    /// by the SessionIssuer), where it can be redacted or aged out; the
    /// privacy rule that keeps credentials off the spine keeps the IP off it
    /// too.
    /// </summary>
    public static DomainEventRecord SessionCreated(
        Guid sessionId,
        Guid userId,
        string? device,
        DateTimeOffset now) => new()
        {
            Id = Ids.NewId(now),
            OccurredAt = now,
            Module = Module,
            EventType = "identity.session.created",
            EntityId = sessionId,
            ActorUserId = userId,
            Payload = JsonSerializer.Serialize(new { device }, Json),
        };

    /// <summary>
    /// identity.session.revoked with reason refresh_reuse:
    /// a rotated or revoked refresh token was presented again, so the
    /// whole family is dead and the user gets a security notice.
    /// Actor is null: the presenter is untrusted.
    /// </summary>
    public static DomainEventRecord FamilyRevokedForReuse(
        Guid presentedSessionId,
        DateTimeOffset now) => new()
        {
            Id = Ids.NewId(now),
            OccurredAt = now,
            Module = Module,
            EventType = "identity.session.revoked",
            EntityId = presentedSessionId,
            ActorUserId = null,
            Payload = JsonSerializer.Serialize(new { reason = "refresh_reuse" }, Json),
        };
}
