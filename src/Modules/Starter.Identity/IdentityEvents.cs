using System.Text.Json;
using Starter.Platform.Events;
using Starter.SharedKernel;

namespace Starter.Identity;

/// <summary>
/// The identity rows of the doc 09 section 3.1 catalogue this story
/// produces. Payloads follow the doc 09 privacy rule: ids and coarse
/// metadata only - never the email address or any credential material.
/// </summary>
internal static class IdentityEvents
{
    private const string Module = "identity";

    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    /// <summary>
    /// identity.user.registered (doc 09 3.1): account created. Method is
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
    /// identity.auth_method.linked (doc 09 3.1): a new credential attached
    /// to an EXISTING account (SRS 5.3 / doc 10 4.5 linking; a brand-new
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
    /// identity.password.changed (doc 09 3.1): self-service credential
    /// change; #35's slice is the passwordless account setting its first
    /// password (FR-AUTH-03 dual-method). N:security notifies.
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
    /// identity.registration.reattempted (doc 09 3.1): someone submitted a
    /// registration for an email that already has an account (SRS 5.3).
    /// The responder returned the same success as a fresh registration;
    /// this event carries the "was this you?" notice to the notifications
    /// consumer (#19). Actor is null: the submitter is unauthenticated and
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
    /// identity.user.verified (doc 09 3.1): the email address is proven.
    /// #34's verify_email token flow emits this for password accounts;
    /// #35's Google sign-in emits it when claiming or creating a
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

    /// <summary>identity.session.created (doc 09 3.1): login.</summary>
    public static DomainEventRecord SessionCreated(
        Guid sessionId,
        Guid userId,
        string? device,
        string? ip,
        DateTimeOffset now) => new()
        {
            Id = Ids.NewId(now),
            OccurredAt = now,
            Module = Module,
            EventType = "identity.session.created",
            EntityId = sessionId,
            ActorUserId = userId,
            Payload = JsonSerializer.Serialize(new { device, ip }, Json),
        };

    /// <summary>
    /// identity.session.revoked (doc 09 3.1) with reason refresh_reuse:
    /// a rotated or revoked refresh token was presented again, so the
    /// whole family is dead and the user gets a security notice
    /// (FR-AUTH-04/11). Actor is null: the presenter is untrusted.
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
