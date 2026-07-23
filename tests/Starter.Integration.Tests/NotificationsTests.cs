using System.Net;
using System.Text.Json;
using Npgsql;
using Shouldly;
using Starter.Integration.Tests.Fixtures;
using Xunit;

namespace Starter.Integration.Tests;

/// <summary>
/// The in-app notifications inbox (in-app-notifications.md section 9), driven
/// through the real endpoints and the real Fast-lane projection. Proves: the
/// projection fires for each curated type at the CORRECT recipient (especially
/// that membership.created notifies the joining member, the actor-is-recipient
/// case a naive exclusion check would drop, and that the three admin-driven events
/// notify the affected member, not the acting admin); a non-curated event produces
/// nothing; redelivery is idempotent; cross-tenant and cross-user isolation hold
/// (a foreign id marks-read as 404 and stays unread); mark-one / mark-all /
/// unread-count; and keyset list pagination with the unread filter.
/// </summary>
[Collection(StarterCollectionDefinition.Name)]
public sealed class NotificationsTests(StarterAppFixture fixture)
{
    private const string MembershipCreated = "tenancy.membership.created";
    private const string MemberRoleChanged = "tenancy.member.role_changed";
    private const string TeamMemberAdded = "tenancy.team.member_added";
    private const string OwnershipTransferred = "tenancy.ownership.transferred";

    [Fact]
    public async Task MembershipCreated_NotifiesTheJoiningMember_OwnerAndInvitedMember()
    {
        var cancellationToken = TestContext.Current.CancellationToken;

        // The owner's own signup membership: the actor IS the joining member, so
        // the owner is notified "you joined as owner".
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);
        var ownerJoin = await WaitForTypeAsync(owner.Token, MembershipCreated, cancellationToken);
        ownerJoin.Data.GetProperty("role").GetString().ShouldBe("owner");

        // An invited member: the actor on their membership.created IS themselves,
        // so the member (not the inviting owner) is notified "you joined as member".
        var member = await TenantWorkflow.InviteAcceptMintAsync(fixture, owner, "member", cancellationToken);
        var memberJoin = await WaitForTypeAsync(member.Token, MembershipCreated, cancellationToken);
        memberJoin.Data.GetProperty("role").GetString().ShouldBe("member");
    }

    [Fact]
    public async Task AdminDrivenEvents_NotifyTheAffectedMember_NotTheActingAdmin()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);
        var member = await TenantWorkflow.InviteAcceptMintAsync(fixture, owner, "member", cancellationToken);

        // The owner (the acting admin) adds the member to a team: the ADDED user is
        // notified, and the render data carries the team id.
        var teamId = await TenantWorkflow.CreateTeamAsync(fixture, owner.Token, TenantWorkflow.FreshSlug(), "Core", cancellationToken);
        await TenantWorkflow.AddTeamMemberAsync(fixture, owner.Token, teamId, member.UserId, cancellationToken);
        var added = await WaitForTypeAsync(member.Token, TeamMemberAdded, cancellationToken);
        added.Data.GetProperty("teamId").GetGuid().ShouldBe(teamId);

        // The owner changes the member's role: the AFFECTED member is notified with
        // the new role, not the acting owner.
        var change = await TenantWorkflow.PatchJsonAsync(
            fixture, $"/api/v1/tenant/members/{member.UserId}", owner.Token, new { role = "admin" }, cancellationToken);
        change.StatusCode.ShouldBe(HttpStatusCode.NoContent);
        var roleChanged = await WaitForTypeAsync(member.Token, MemberRoleChanged, cancellationToken);
        roleChanged.Data.GetProperty("role").GetString().ShouldBe("admin");

        // The acting owner is NEVER the recipient of the admin-driven events: their
        // inbox holds only their own signup membership.created.
        var (ownerItems, _) = await ListAsync(owner.Token, string.Empty, cancellationToken);
        ownerItems.ShouldAllBe(item => item.Type == MembershipCreated);
        ownerItems.Count.ShouldBe(1);
    }

    [Fact]
    public async Task OwnershipTransferred_NotifiesTheNewOwner_WithThePreviousOwner()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);
        var member = await TenantWorkflow.InviteAcceptMintAsync(fixture, owner, "member", cancellationToken);

        var transfer = await TenantWorkflow.PostJsonAsync(
            fixture, "/api/v1/tenant/transfer-ownership", owner.Token, new { userId = member.UserId }, cancellationToken);
        transfer.StatusCode.ShouldBe(HttpStatusCode.NoContent);

        // The NEW owner (the member) is notified; the render data names the previous
        // owner (the acting user).
        var transferred = await WaitForTypeAsync(member.Token, OwnershipTransferred, cancellationToken);
        transferred.Data.GetProperty("previousOwnerUserId").GetGuid().ShouldBe(owner.UserId);
    }

    [Fact]
    public async Task NonCuratedEvent_ProducesNoNotification()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);

        // The owner's signup notification must be projected first, so the final
        // count assertion isolates "the note produced no row".
        await WaitForTypeAsync(owner.Token, MembershipCreated, cancellationToken);

        // A note create emits sample.note.created: tenant-scoped and audited, but
        // NOT in the curated notification set.
        var create = await TenantWorkflow.CreateNoteAsync(fixture, owner.Token, "Not a notice", cancellationToken);
        create.StatusCode.ShouldBe(HttpStatusCode.Created);
        using var created = await HttpTestHelpers.ReadJsonAsync(create, cancellationToken);
        var noteId = created.RootElement.GetProperty("id").GetGuid();

        // Wait until the note's Fast outbox row is delivered: the notification
        // consumer shares that row and runs in the same send, so a delivered row
        // means the projection has definitively run for this event.
        var eventId = await WaitForNoteEventIdAsync(noteId, cancellationToken);
        await WaitUntilAsync(
            async () => await CountAsync(
                "select count(*) from platform.outbox where event_id = @id and lane = 'fast' "
                + "and delivered_at is not null and poisoned_at is null",
                cancellationToken,
                ("id", eventId)) == 1,
            cancellationToken);

        // No notification row was projected for that event.
        (await CountAsync(
            "select count(*) from platform.notifications where source_event_id = @id",
            cancellationToken,
            ("id", eventId))).ShouldBe(0);

        // The owner's inbox still holds only their signup membership.created.
        var (items, _) = await ListAsync(owner.Token, string.Empty, cancellationToken);
        items.Count.ShouldBe(1);
        items.ShouldNotContain(item => item.Type == "sample.note.created");
    }

    [Fact]
    public async Task Redelivery_IsIdempotent_NoDuplicateRow()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);
        await WaitForTypeAsync(owner.Token, MembershipCreated, cancellationToken);

        // Exactly one notification for the owner; capture its source event id.
        (await CountAsync(
            "select count(*) from platform.notifications where recipient_user_id = @id",
            cancellationToken,
            ("id", owner.UserId))).ShouldBe(1);
        var eventId = await SingleGuidAsync(
            "select source_event_id from platform.notifications where recipient_user_id = @id",
            cancellationToken,
            ("id", owner.UserId));

        // Force a redelivery: null out the Fast-lane outbox row so the dispatcher
        // re-claims and re-delivers it to every Fast consumer.
        await PlatformWorkflow.ExecuteAsync(
            fixture,
            "update platform.outbox set delivered_at = null, next_attempt_at = now() "
            + "where event_id = @id and lane = 'fast'",
            cancellationToken,
            ("id", eventId));

        // The redelivery is handled and re-marked delivered (the unique-violation
        // the consumer treats as success), not poisoned...
        await WaitUntilAsync(
            async () => await CountAsync(
                "select count(*) from platform.outbox "
                + "where event_id = @id and lane = 'fast' and delivered_at is not null and poisoned_at is null",
                cancellationToken,
                ("id", eventId)) == 1,
            cancellationToken);

        // ...and it produced no second notification row.
        (await CountAsync(
            "select count(*) from platform.notifications where source_event_id = @id",
            cancellationToken,
            ("id", eventId))).ShouldBe(1);
    }

    [Fact]
    public async Task CrossTenantIsolation_SameUser_SeesOnlyTheActiveTenantsInbox()
    {
        var cancellationToken = TestContext.Current.CancellationToken;

        // One physical user, a member of two tenants. Each tenant's inbox is its
        // own: a caller acting in tenant B never sees tenant C's rows (RLS).
        var email = TenantWorkflow.FreshEmail("multi");
        var userToken = await fixture.RegisterVerifyLoginAsync(email, TenantWorkflow.Password, cancellationToken);

        var ownerB = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);
        var ownerC = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);

        var tokenB = await OnboardExistingMemberAsync(ownerB, email, userToken, cancellationToken);
        var tokenC = await OnboardExistingMemberAsync(ownerC, email, userToken, cancellationToken);

        var inB = await WaitForTypeAsync(tokenB, MembershipCreated, cancellationToken);
        var inC = await WaitForTypeAsync(tokenC, MembershipCreated, cancellationToken);

        // Acting in tenant B sees exactly one row; acting in tenant C sees exactly
        // one row; the two are different rows, and neither tenant's inbox contains
        // the other's row.
        var (itemsB, _) = await ListAsync(tokenB, string.Empty, cancellationToken);
        var (itemsC, _) = await ListAsync(tokenC, string.Empty, cancellationToken);
        itemsB.Count.ShouldBe(1);
        itemsC.Count.ShouldBe(1);
        inB.Id.ShouldNotBe(inC.Id);
        itemsB.ShouldNotContain(item => item.Id == inC.Id);
        itemsC.ShouldNotContain(item => item.Id == inB.Id);
    }

    [Fact]
    public async Task CrossUserIsolation_MarkReadForeignId_Is404_AndLeavesItUnread()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);
        var member = await TenantWorkflow.InviteAcceptMintAsync(fixture, owner, "member", cancellationToken);

        // The member's own join notification.
        var memberJoin = await WaitForTypeAsync(member.Token, MembershipCreated, cancellationToken);

        // The owner never sees the member's notification (recipient filter), so the
        // owner's inbox holds only their own row.
        var (ownerItems, _) = await ListAsync(owner.Token, string.Empty, cancellationToken);
        ownerItems.ShouldNotContain(item => item.Id == memberJoin.Id);

        // The owner marking the member's notification id reads as 404 (invisible),
        // never 403.
        var foreignMark = await TenantWorkflow.PostJsonAsync(
            fixture, $"/api/v1/tenant/notifications/{memberJoin.Id}/read", owner.Token, new { }, cancellationToken);
        foreignMark.StatusCode.ShouldBe(HttpStatusCode.NotFound);
        using (var problem = await HttpTestHelpers.ReadJsonAsync(foreignMark, cancellationToken))
        {
            problem.RootElement.GetProperty("type").GetString().ShouldBe("starter:not-found");
        }

        // The member's row is still unread: the foreign mark touched nothing.
        (await UnreadCountAsync(member.Token, cancellationToken)).ShouldBe(1);
        var (memberItems, _) = await ListAsync(member.Token, string.Empty, cancellationToken);
        memberItems.Single(item => item.Id == memberJoin.Id).Read.ShouldBeFalse();
    }

    [Fact]
    public async Task MarkOne_MarkAll_AndUnreadCount()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);
        var member = await TenantWorkflow.InviteAcceptMintAsync(fixture, owner, "member", cancellationToken);

        // Give the member three notifications: join + team-add + role-change.
        var teamId = await TenantWorkflow.CreateTeamAsync(fixture, owner.Token, TenantWorkflow.FreshSlug(), "Ops", cancellationToken);
        await TenantWorkflow.AddTeamMemberAsync(fixture, owner.Token, teamId, member.UserId, cancellationToken);
        var change = await TenantWorkflow.PatchJsonAsync(
            fixture, $"/api/v1/tenant/members/{member.UserId}", owner.Token, new { role = "admin" }, cancellationToken);
        change.StatusCode.ShouldBe(HttpStatusCode.NoContent);

        await WaitForCountAsync(member.Token, 3, cancellationToken);
        (await UnreadCountAsync(member.Token, cancellationToken)).ShouldBe(3);

        // Mark one read: the unread count drops by one.
        var (items, _) = await ListAsync(member.Token, string.Empty, cancellationToken);
        var first = items[0].Id;
        (await MarkReadAsync(member.Token, first, cancellationToken)).ShouldBe(HttpStatusCode.NoContent);
        (await UnreadCountAsync(member.Token, cancellationToken)).ShouldBe(2);

        // Mark-read is idempotent: marking the same row again is still success and
        // does not change the count.
        (await MarkReadAsync(member.Token, first, cancellationToken)).ShouldBe(HttpStatusCode.NoContent);
        (await UnreadCountAsync(member.Token, cancellationToken)).ShouldBe(2);

        // Mark-all read: it flips exactly the remaining two unread rows and reports
        // the count marked; the unread count is then zero.
        var readAll = await TenantWorkflow.PostJsonAsync(
            fixture, "/api/v1/tenant/notifications/read-all", member.Token, new { }, cancellationToken);
        readAll.StatusCode.ShouldBe(HttpStatusCode.OK);
        using (var doc = await HttpTestHelpers.ReadJsonAsync(readAll, cancellationToken))
        {
            doc.RootElement.GetProperty("marked").GetInt32().ShouldBe(2);
        }

        (await UnreadCountAsync(member.Token, cancellationToken)).ShouldBe(0);
    }

    [Fact]
    public async Task List_KeysetPaginated_NewestFirst_AndUnreadFilter()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var owner = await TenantWorkflow.SignupOwnerAsync(fixture, cancellationToken);
        var member = await TenantWorkflow.InviteAcceptMintAsync(fixture, owner, "member", cancellationToken);

        var teamId = await TenantWorkflow.CreateTeamAsync(fixture, owner.Token, TenantWorkflow.FreshSlug(), "Squad", cancellationToken);
        await TenantWorkflow.AddTeamMemberAsync(fixture, owner.Token, teamId, member.UserId, cancellationToken);
        var change = await TenantWorkflow.PatchJsonAsync(
            fixture, $"/api/v1/tenant/members/{member.UserId}", owner.Token, new { role = "admin" }, cancellationToken);
        change.StatusCode.ShouldBe(HttpStatusCode.NoContent);
        await WaitForCountAsync(member.Token, 3, cancellationToken);

        // Page one row at a time; collect ids across pages until the cursor runs out.
        var paged = new List<InboxItem>();
        string? cursor = null;
        var guard = 0;
        do
        {
            var query = cursor is null ? "?limit=1" : $"?limit=1&cursor={Uri.EscapeDataString(cursor)}";
            var (pageItems, next) = await ListAsync(member.Token, query, cancellationToken);
            pageItems.Count.ShouldBeLessThanOrEqualTo(1);
            paged.AddRange(pageItems);
            cursor = next;
            (++guard).ShouldBeLessThan(10, "keyset paging must terminate");
        }
        while (cursor is not null);

        // All three rows, no duplicates, and strictly newest-first by created_at.
        paged.Count.ShouldBe(3);
        paged.Select(item => item.Id).Distinct().Count().ShouldBe(3);
        paged.Select(item => item.CreatedAt).ShouldBe(paged.Select(item => item.CreatedAt).OrderByDescending(value => value));

        // Mark the newest read, then ?unread=true excludes exactly it.
        (await MarkReadAsync(member.Token, paged[0].Id, cancellationToken)).ShouldBe(HttpStatusCode.NoContent);
        var (unreadItems, _) = await ListAsync(member.Token, "?unread=true", cancellationToken);
        unreadItems.Count.ShouldBe(2);
        unreadItems.ShouldNotContain(item => item.Id == paged[0].Id);
        unreadItems.ShouldAllBe(item => !item.Read);
    }

    // --- HTTP helpers ----------------------------------------------------

    private async Task<(List<InboxItem> Items, string? NextCursor)> ListAsync(
        string token, string query, CancellationToken cancellationToken)
    {
        var response = await TenantWorkflow.GetAsync(
            fixture, "/api/v1/tenant/notifications" + query, token, cancellationToken);
        response.StatusCode.ShouldBe(HttpStatusCode.OK);
        using var doc = await HttpTestHelpers.ReadJsonAsync(response, cancellationToken);
        var root = doc.RootElement;
        var items = root.GetProperty("items").EnumerateArray()
            .Select(element => new InboxItem(
                element.GetProperty("id").GetGuid(),
                element.GetProperty("type").GetString()!,
                element.GetProperty("data").Clone(),
                element.GetProperty("createdAt").GetDateTimeOffset(),
                element.TryGetProperty("readAt", out var readAt) && readAt.ValueKind != JsonValueKind.Null))
            .ToList();
        var nextCursor = root.TryGetProperty("nextCursor", out var cursor) && cursor.ValueKind == JsonValueKind.String
            ? cursor.GetString()
            : null;
        return (items, nextCursor);
    }

    private async Task<int> UnreadCountAsync(string token, CancellationToken cancellationToken)
    {
        var response = await TenantWorkflow.GetAsync(
            fixture, "/api/v1/tenant/notifications/unread-count", token, cancellationToken);
        response.StatusCode.ShouldBe(HttpStatusCode.OK);
        using var doc = await HttpTestHelpers.ReadJsonAsync(response, cancellationToken);
        return doc.RootElement.GetProperty("count").GetInt32();
    }

    private async Task<HttpStatusCode> MarkReadAsync(
        string token, Guid id, CancellationToken cancellationToken)
    {
        var response = await TenantWorkflow.PostJsonAsync(
            fixture, $"/api/v1/tenant/notifications/{id}/read", token, new { }, cancellationToken);
        return response.StatusCode;
    }

    private async Task<InboxItem> WaitForTypeAsync(
        string token, string type, CancellationToken cancellationToken)
    {
        var deadline = DateTimeOffset.UtcNow + TimeSpan.FromSeconds(30);
        while (DateTimeOffset.UtcNow < deadline)
        {
            var (items, _) = await ListAsync(token, string.Empty, cancellationToken);
            var match = items.FirstOrDefault(item => item.Type == type);
            if (match is not null)
            {
                return match;
            }

            await Task.Delay(200, cancellationToken);
        }

        throw new InvalidOperationException($"No '{type}' notification appeared within the deadline.");
    }

    private async Task WaitForCountAsync(string token, int atLeast, CancellationToken cancellationToken)
    {
        var deadline = DateTimeOffset.UtcNow + TimeSpan.FromSeconds(30);
        while (DateTimeOffset.UtcNow < deadline)
        {
            var (items, _) = await ListAsync(token, "?limit=100", cancellationToken);
            if (items.Count >= atLeast)
            {
                return;
            }

            await Task.Delay(200, cancellationToken);
        }

        throw new InvalidOperationException($"Fewer than {atLeast} notifications appeared within the deadline.");
    }

    /// <summary>
    /// Onboards an EXISTING (already registered + verified) user into another
    /// tenant: the owner invites the email, the user accepts with their own token,
    /// and a tid-bound token for that tenant is minted. Mirrors
    /// TenantWorkflow.InviteAcceptMintAsync but reuses the caller's account so the
    /// same physical user ends up a member of several tenants.
    /// </summary>
    private async Task<string> OnboardExistingMemberAsync(
        OwnerContext owner, string email, string inviteeToken, CancellationToken cancellationToken)
    {
        var invite = await TenantWorkflow.PostJsonAsync(
            fixture, "/api/v1/tenant/invitations", owner.Token, new { email, role = "member" }, cancellationToken);
        invite.StatusCode.ShouldBe(HttpStatusCode.Created);

        var invitationEmail = fixture.Emails.Sent.Last(
            message => message.To == email && message.Subject.Contains("invited", StringComparison.Ordinal));
        var rawToken = HttpTestHelpers.ExtractVerificationToken(invitationEmail);

        var accept = await TenantWorkflow.PostJsonAsync(
            fixture, "/api/v1/invitations/accept", inviteeToken, new { token = rawToken }, cancellationToken);
        accept.StatusCode.ShouldBe(HttpStatusCode.OK);

        return await TenantWorkflow.MintTenantTokenAsync(fixture, owner.TenantId, inviteeToken, cancellationToken);
    }

    // --- SQL / timing helpers --------------------------------------------

    private async Task<Guid> WaitForNoteEventIdAsync(Guid noteId, CancellationToken cancellationToken)
    {
        var deadline = DateTimeOffset.UtcNow + TimeSpan.FromSeconds(30);
        while (DateTimeOffset.UtcNow < deadline)
        {
            var eventId = await SingleGuidAsync(
                "select id from platform.domain_events where event_type = 'sample.note.created' and entity_id = @id",
                cancellationToken,
                ("id", noteId));
            if (eventId != Guid.Empty)
            {
                return eventId;
            }

            await Task.Delay(200, cancellationToken);
        }

        throw new InvalidOperationException("The note's domain event did not appear within the deadline.");
    }

    private async Task<int> CountAsync(
        string sql, CancellationToken cancellationToken, params (string Name, object Value)[] parameters) =>
        (int)await PlatformWorkflow.CountAsync(fixture, sql, cancellationToken, parameters);

    private async Task<Guid> SingleGuidAsync(
        string sql, CancellationToken cancellationToken, params (string Name, object Value)[] parameters)
    {
        await using var connection = await fixture.OpenConnectionAsync(cancellationToken);
        await using var command = new NpgsqlCommand(sql, connection);
        foreach (var (name, value) in parameters)
        {
            command.Parameters.AddWithValue(name, value);
        }

        var result = await command.ExecuteScalarAsync(cancellationToken);
        return result is Guid id ? id : Guid.Empty;
    }

    private static async Task WaitUntilAsync(Func<Task<bool>> condition, CancellationToken cancellationToken)
    {
        var deadline = DateTimeOffset.UtcNow + TimeSpan.FromSeconds(30);
        while (DateTimeOffset.UtcNow < deadline)
        {
            if (await condition())
            {
                return;
            }

            await Task.Delay(200, cancellationToken);
        }

        throw new InvalidOperationException("The awaited condition did not hold within the deadline.");
    }

    private sealed record InboxItem(Guid Id, string Type, JsonElement Data, DateTimeOffset CreatedAt, bool Read);
}
