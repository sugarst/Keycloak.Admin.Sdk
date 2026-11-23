using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;

namespace Keycloak.Admin.Sdk;

public enum AdminErrorBodyState
{
    Complete,
    Truncated,
    ReadFailed
}

/// <summary>HTTP error headers and the captured bytes of the response body. May contain sensitive data.</summary>
public sealed class AdminErrorResponse : AdminResponse
{
    private const int MaxContentBytes = 64 * 1024;
    private static readonly TimeSpan ReadTimeout = TimeSpan.FromSeconds(2);

    private AdminErrorResponse(HttpResponseMessage response, byte[] bytes, AdminErrorBodyState bodyState)
        : base(response.StatusCode, response.Headers.Location, SnapshotHeaders(response), bytes)
    {
        BodyState = bodyState;
        ContentType = response.Content.Headers.NonValidated.TryGetValues("Content-Type", out var values)
            ? values.ToString()
            : null;
    }

    /// <summary>Whether Content contains the complete body, a size-limited prefix, or bytes read before a failure.</summary>
    public AdminErrorBodyState BodyState { get; }
    /// <summary>The original Content-Type header, when present.</summary>
    public string? ContentType { get; }

    internal static async Task<AdminErrorResponse> ReadAsync(HttpResponseMessage response, CancellationToken cancellationToken)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(ReadTimeout);
        using var captured = new LimitedBodyStream();
        try
        {
            await response.Content.CopyToAsync(captured, deadline.Token).ConfigureAwait(false);
            return new(response, captured.ToArray(), AdminErrorBodyState.Complete);
        }
        catch (BodyLimitReachedException)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return new(response, captured.ToArray(), AdminErrorBodyState.Truncated);
        }
        catch (Exception error) when (error is IOException or HttpRequestException or InvalidOperationException or OperationCanceledException)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return new(response, captured.ToArray(), AdminErrorBodyState.ReadFailed);
        }
    }

    internal string? GetDisplayMessage()
    {
        if (StatusCode != HttpStatusCode.BadRequest || BodyState != AdminErrorBodyState.Complete || Content.IsEmpty
            || !MediaTypeHeaderValue.TryParse(ContentType, out var type) || type.MediaType is not string mediaType
            || !(mediaType.Equals("application/json", StringComparison.OrdinalIgnoreCase) || mediaType.EndsWith("+json", StringComparison.OrdinalIgnoreCase)))
            return null;

        try
        {
            using var document = JsonDocument.Parse(Content);
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object || !root.TryGetProperty("errorMessage", out var message)
                || message.ValueKind != JsonValueKind.String)
                return null;

            // Never include values reflected from a request in the legacy exception message.
            return message.GetString() switch
            {
                "Organization cannot be null." or "Group name is missing" or "Group representation is missing"
                    or "Domain name cannot be empty" or "Could not create user" => message.GetString(),
                string text when text.StartsWith("The specified domain is invalid: '", StringComparison.Ordinal)
                    => "The specified domain is invalid.",
                _ => null
            };
        }
        catch (JsonException) { return null; }
    }

    private sealed class BodyLimitReachedException : Exception;

    // Limit writes as they arrive so custom HttpContent implementations are bounded too.
    private sealed class LimitedBodyStream : Stream
    {
        private readonly MemoryStream buffer = new();

        public byte[] ToArray() => buffer.ToArray();
        public override bool CanRead => false;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override int Read(byte[] array, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] array, int offset, int count) => Write(array.AsSpan(offset, count));

        public override void Write(ReadOnlySpan<byte> bytes)
        {
            int count = Math.Min(bytes.Length, MaxContentBytes - (int)buffer.Length);
            buffer.Write(bytes[..count]);
            if (count < bytes.Length) throw new BodyLimitReachedException();
        }

        public override Task WriteAsync(byte[] array, int offset, int count, CancellationToken cancellationToken)
            => WriteAsync(array.AsMemory(offset, count), cancellationToken).AsTask();

        public override ValueTask WriteAsync(ReadOnlyMemory<byte> bytes, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Write(bytes.Span);
            return ValueTask.CompletedTask;
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing) buffer.Dispose();
            base.Dispose(disposing);
        }
    }
}
