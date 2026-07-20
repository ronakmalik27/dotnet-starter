namespace Starter.Platform.Paging;

/// <summary>
/// A page of keyset (cursor) paginated results: the items on this page plus
/// an opaque cursor for the next page, or null when this is the last page.
/// This is the pagination convention modules copy - keyset over offset, so
/// page latency stays flat as the offset grows and no row is skipped or
/// repeated when rows are inserted between page reads. The endpoint layer
/// serializes this straight to the wire as
/// <c>{ "items": [...], "nextCursor": "..." | null }</c>.
/// </summary>
/// <typeparam name="T">The shaped item type the endpoint returns.</typeparam>
public sealed record CursorPage<T>(IReadOnlyList<T> Items, string? NextCursor);
