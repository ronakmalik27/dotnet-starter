using System.Net;
using Shouldly;
using Starter.Integration.Tests.Fixtures;
using Xunit;

namespace Starter.Integration.Tests;

/// <summary>
/// Audited, time-boxed, revocable impersonation (multi-tenancy.md sections 7 and
/// 9), driven through the real endpoints. Proves: starting a session writes the
/// grant row AND emits ImpersonationStarted in one transaction (no token without
/// audit); the minted token carries imp + tid and works against the target
/// tenant; a destructive op under imp is refused; ending a grant blocks the next
/// imp request immediately; and an expired grant is rejected at the guard, not
/// only at token expiry.
/// </summary>
[Collection(StarterCollectionDefinition.Name)]
public sealed class ImpersonationTests(StarterAppFixture fixture)
{
    private const string Reason = "Investigating a support ticket.";

    [Fact]
    public async Task Start_WritesGrantAndEvent_AndTokenReadsTheTenant()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var admin = await PlatformWorkflow.SignupPlatformAdminAsync(fixture, cancellationToken);
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);
        var noteId = await CreateOwnerNoteAsync(owner, cancellationToken);

        var (impToken, grantId) = await PlatformWorkflow.StartImpersonationAsync(
            fixture, admin.Token, owner.TenantId, owner.UserId, Reason, cancellationToken);

        // No token without audit: the grant row exists after a successful start.
        var grants = await PlatformWorkflow.CountAsync(
            fixture,
            "select count(*) from platform.impersonation_grants where id = @id",
            cancellationToken,
            ("id", grantId));
        grants.ShouldBe(1);

        // The ImpersonationStarted event landed on the spine (same transaction).
        var events = await PlatformWorkflow.CountAsync(
            fixture,
            "select count(*) from platform.domain_events "
            + "where event_type = 'platform.impersonation.started' and entity_id = @id",
            cancellationToken,
            ("id", grantId));
        events.ShouldBe(1);

        // The minted token carries imp (the acting admin) and tid (the tenant).
        HttpTestHelpers.ReadClaim(impToken, "imp").ShouldBe(admin.UserId.ToString());
        HttpTestHelpers.ReadClaim(impToken, "tid").ShouldBe(owner.TenantId.ToString());

        // It works against the target tenant: it can read the owner's note (sub is
        // the owner, tid scopes RLS to the tenant).
        var read = await PlatformWorkflow.GetAsync(
            fixture, $"/api/v1/sample/notes/{noteId}", impToken, cancellationToken);
        read.StatusCode.ShouldBe(HttpStatusCode.OK);
    }

    [Fact]
    public async Task DestructiveOp_UnderImpersonation_IsRefused()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var admin = await PlatformWorkflow.SignupPlatformAdminAsync(fixture, cancellationToken);
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);
        var noteId = await CreateOwnerNoteAsync(owner, cancellationToken);

        var (impToken, _) = await PlatformWorkflow.StartImpersonationAsync(
            fixture, admin.Token, owner.TenantId, owner.UserId, Reason, cancellationToken);

        // The owner could delete their own note - but under impersonation the
        // destructive op is refused with the conservative-default 403.
        var delete = await TenantWorkflow.DeleteAsync(
            fixture, $"/api/v1/sample/notes/{noteId}", impToken, cancellationToken);
        delete.StatusCode.ShouldBe(HttpStatusCode.Forbidden);
        using var doc = await HttpTestHelpers.ReadJsonAsync(delete, cancellationToken);
        doc.RootElement.GetProperty("type").GetString().ShouldBe("starter:impersonation-forbidden");

        // The note still exists (the delete never ran): a normal owner token deletes it.
        var deleteAsOwner = await TenantWorkflow.DeleteAsync(
            fixture, $"/api/v1/sample/notes/{noteId}", owner.Token, cancellationToken);
        deleteAsOwner.StatusCode.ShouldBe(HttpStatusCode.NoContent);
    }

    [Fact]
    public async Task EndingAGrant_BlocksTheNextImpRequest_Immediately()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var admin = await PlatformWorkflow.SignupPlatformAdminAsync(fixture, cancellationToken);
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);
        var noteId = await CreateOwnerNoteAsync(owner, cancellationToken);

        var (impToken, grantId) = await PlatformWorkflow.StartImpersonationAsync(
            fixture, admin.Token, owner.TenantId, owner.UserId, Reason, cancellationToken);

        // The session works before ending.
        var beforeEnd = await PlatformWorkflow.GetAsync(
            fixture, $"/api/v1/sample/notes/{noteId}", impToken, cancellationToken);
        beforeEnd.StatusCode.ShouldBe(HttpStatusCode.OK);

        // End the grant.
        var end = await TenantWorkflow.PostJsonAsync(
            fixture, $"/api/v1/platform/impersonation/{grantId}/end", admin.Token, new { }, cancellationToken);
        end.StatusCode.ShouldBe(HttpStatusCode.NoContent);

        // The very next imp request is rejected by the per-request guard (401),
        // even though the short token itself has not expired.
        var afterEnd = await PlatformWorkflow.GetAsync(
            fixture, $"/api/v1/sample/notes/{noteId}", impToken, cancellationToken);
        afterEnd.StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
        using var doc = await HttpTestHelpers.ReadJsonAsync(afterEnd, cancellationToken);
        doc.RootElement.GetProperty("type").GetString().ShouldBe("starter:impersonation-ended");

        // Ending again is an idempotent no-op success.
        var endAgain = await TenantWorkflow.PostJsonAsync(
            fixture, $"/api/v1/platform/impersonation/{grantId}/end", admin.Token, new { }, cancellationToken);
        endAgain.StatusCode.ShouldBe(HttpStatusCode.NoContent);
    }

    [Fact]
    public async Task ExpiredGrant_IsRejected_AtTheGuard()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var admin = await PlatformWorkflow.SignupPlatformAdminAsync(fixture, cancellationToken);
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);
        var noteId = await CreateOwnerNoteAsync(owner, cancellationToken);

        var (impToken, grantId) = await PlatformWorkflow.StartImpersonationAsync(
            fixture, admin.Token, owner.TenantId, owner.UserId, Reason, cancellationToken);

        // Force the grant past its expiry (the short JWT itself is still valid).
        // The guard checks expires_at against the database clock, so an expired
        // grant is rejected on the next request.
        await PlatformWorkflow.ExecuteAsync(
            fixture,
            "update platform.impersonation_grants set expires_at = now() - interval '1 minute' where id = @id",
            cancellationToken,
            ("id", grantId));

        var afterExpiry = await PlatformWorkflow.GetAsync(
            fixture, $"/api/v1/sample/notes/{noteId}", impToken, cancellationToken);
        afterExpiry.StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
        using var doc = await HttpTestHelpers.ReadJsonAsync(afterExpiry, cancellationToken);
        doc.RootElement.GetProperty("type").GetString().ShouldBe("starter:impersonation-ended");
    }

    [Fact]
    public async Task Start_WithoutTargetUser_ActsAsTheAdmin_AndGrantHasNullTargetUser()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var admin = await PlatformWorkflow.SignupPlatformAdminAsync(fixture, cancellationToken);
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);

        // No target user: the session acts as the admin themselves in the tenant.
        var (impToken, grantId) = await PlatformWorkflow.StartImpersonationAsync(
            fixture, admin.Token, owner.TenantId, targetUserId: null, Reason, cancellationToken);

        HttpTestHelpers.ReadClaim(impToken, "sub").ShouldBe(admin.UserId.ToString());
        HttpTestHelpers.ReadClaim(impToken, "imp").ShouldBe(admin.UserId.ToString());
        HttpTestHelpers.ReadClaim(impToken, "tid").ShouldBe(owner.TenantId.ToString());

        // The grant row exists with a null target user (the null bound correctly).
        var nullTargetGrants = await PlatformWorkflow.CountAsync(
            fixture,
            "select count(*) from platform.impersonation_grants where id = @id and target_user_id is null",
            cancellationToken,
            ("id", grantId));
        nullTargetGrants.ShouldBe(1);
    }

    private async Task<Guid> CreateOwnerNoteAsync(OwnerContext owner, CancellationToken cancellationToken)
    {
        var create = await TenantWorkflow.CreateNoteAsync(fixture, owner.Token, "Owner note", cancellationToken);
        create.StatusCode.ShouldBe(HttpStatusCode.Created);
        using var doc = await HttpTestHelpers.ReadJsonAsync(create, cancellationToken);
        return doc.RootElement.GetProperty("id").GetGuid();
    }
}
