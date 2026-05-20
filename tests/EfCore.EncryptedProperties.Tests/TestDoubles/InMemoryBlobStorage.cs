using System.Collections.Concurrent;
using Azure;
using Azure.Core;
using Azure.Storage.Blobs;
using Azure.Storage.Blobs.Models;

namespace EfCore.EncryptedProperties.Tests.TestDoubles;

internal sealed class InMemoryBlobContainerClient : BlobContainerClient
{
    private readonly ConcurrentDictionary<string, BlobState> _blobs = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, int> _downloadCounts = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, Queue<UploadFailure>> _uploadFailures = new(StringComparer.Ordinal);
    private readonly object _gate = new();

    public int CreateIfNotExistsCalls { get; private set; }
    public int? AlwaysFailUploadsWithStatus { get; set; }

    public override BlobClient GetBlobClient(string blobName)
        => new InMemoryBlobClient(this, blobName);

    public override Task<Response<BlobContainerInfo>> CreateIfNotExistsAsync(
        PublicAccessType publicAccessType = PublicAccessType.None,
        IDictionary<string, string>? metadata = null,
        BlobContainerEncryptionScopeOptions? encryptionScopeOptions = null,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        CreateIfNotExistsCalls++;

        var info = BlobsModelFactory.BlobContainerInfo(
            new ETag($"\"container-{CreateIfNotExistsCalls}\""),
            DateTimeOffset.UtcNow);
        return Task.FromResult(Response.FromValue(info, new TestResponse(201)));
    }

    public override AsyncPageable<BlobItem> GetBlobsAsync(
        BlobTraits traits = BlobTraits.None,
        BlobStates states = BlobStates.None,
        string? prefix = null,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var items = _blobs.Keys
            .Where(name => prefix is null || name.StartsWith(prefix, StringComparison.Ordinal))
            .OrderBy(name => name, StringComparer.Ordinal)
            .Select(name => BlobsModelFactory.BlobItem(
                name,
                deleted: false,
                properties: null!,
                snapshot: null,
                metadata: null))
            .ToArray();

        var page = Page<BlobItem>.FromValues(items, continuationToken: null, new TestResponse(200));
        return AsyncPageable<BlobItem>.FromPages(new[] { page });
    }

    public void SetBlob(string name, string content)
        => SetBlob(name, BinaryData.FromString(content));

    public void SetBlob(string name, byte[] content)
        => SetBlob(name, BinaryData.FromBytes(content));

    public bool ContainsBlob(string name)
        => _blobs.ContainsKey(name);

    public string GetBlobText(string name)
        => _blobs[name].Content.ToString();

    public int GetDownloadCount(string name)
        => _downloadCounts.TryGetValue(name, out var count) ? count : 0;

    public void QueueUploadFailure(string name, int status, Action? beforeThrow = null)
    {
        var failures = _uploadFailures.GetOrAdd(name, _ => new Queue<UploadFailure>());
        lock (failures)
        {
            failures.Enqueue(new UploadFailure(status, beforeThrow));
        }
    }

    private void SetBlob(string name, BinaryData content)
    {
        lock (_gate)
        {
            _blobs[name] = new BlobState(content, CreateEtag());
        }
    }

    private Response<BlobDownloadResult> Download(string name, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        _downloadCounts.AddOrUpdate(name, 1, (_, count) => count + 1);

        if (!_blobs.TryGetValue(name, out var state))
            throw new RequestFailedException(404, $"Blob '{name}' was not found.");

        var details = BlobsModelFactory.BlobDownloadDetails(eTag: state.ETag);
        var result = BlobsModelFactory.BlobDownloadResult(state.Content, details);
        return Response.FromValue(result, new TestResponse(200));
    }

    private Response<BlobContentInfo> Upload(
        string name,
        BinaryData content,
        BlobUploadOptions? options,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (AlwaysFailUploadsWithStatus is { } status)
            throw new RequestFailedException(status, $"Configured upload failure for blob '{name}'.");

        if (_uploadFailures.TryGetValue(name, out var failures))
        {
            UploadFailure? failure = null;
            lock (failures)
            {
                if (failures.Count > 0)
                    failure = failures.Dequeue();
            }

            if (failure is not null)
            {
                failure.BeforeThrow?.Invoke();
                throw new RequestFailedException(failure.Status, $"Configured upload failure for blob '{name}'.");
            }
        }

        lock (_gate)
        {
            var exists = _blobs.TryGetValue(name, out var existing);
            var conditions = options?.Conditions;

            if (conditions?.IfNoneMatch == ETag.All && exists)
                throw new RequestFailedException(412, $"Blob '{name}' already exists.");

            if (conditions?.IfMatch is { } ifMatch
                && (!exists || existing!.ETag != ifMatch))
            {
                throw new RequestFailedException(412, $"Blob '{name}' ETag did not match.");
            }

            var state = new BlobState(content, CreateEtag());
            _blobs[name] = state;

            var info = BlobsModelFactory.BlobContentInfo(
                state.ETag,
                DateTimeOffset.UtcNow,
                contentHash: Array.Empty<byte>(),
                versionId: null,
                encryptionKeySha256: null,
                encryptionScope: null,
                blobSequenceNumber: 0);
            return Response.FromValue(info, new TestResponse(201));
        }
    }

    private static ETag CreateEtag()
        => new($"\"{Guid.NewGuid():N}\"");

    private sealed record BlobState(BinaryData Content, ETag ETag);

    private sealed record UploadFailure(int Status, Action? BeforeThrow);

    private sealed class InMemoryBlobClient : BlobClient
    {
        private readonly InMemoryBlobContainerClient _container;
        private readonly string _name;

        public InMemoryBlobClient(InMemoryBlobContainerClient container, string name)
        {
            _container = container;
            _name = name;
        }

        public override string Name => _name;

        public override Task<Response<BlobDownloadResult>> DownloadContentAsync(
            CancellationToken cancellationToken = default)
            => Task.FromResult(_container.Download(_name, cancellationToken));

        public override Task<Response<BlobContentInfo>> UploadAsync(
            BinaryData content,
            BlobUploadOptions options,
            CancellationToken cancellationToken = default)
            => Task.FromResult(_container.Upload(_name, content, options, cancellationToken));
    }

    private sealed class TestResponse : Response
    {
        public TestResponse(int status)
        {
            Status = status;
        }

        public override int Status { get; }
        public override string ReasonPhrase => string.Empty;
        public override Stream? ContentStream { get; set; }
        public override string ClientRequestId { get; set; } = string.Empty;

        public override void Dispose()
        {
        }

        protected override bool ContainsHeader(string name)
            => false;

        protected override bool TryGetHeader(string name, out string value)
        {
            value = string.Empty;
            return false;
        }

        protected override bool TryGetHeaderValues(string name, out IEnumerable<string> values)
        {
            values = Array.Empty<string>();
            return false;
        }

        protected override IEnumerable<HttpHeader> EnumerateHeaders()
            => Array.Empty<HttpHeader>();
    }
}
