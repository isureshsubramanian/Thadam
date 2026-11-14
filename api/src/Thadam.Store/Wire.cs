using System.Buffers;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace Thadam.Store;

/// <summary>
/// The length-prefixed binary encoding that the hash chains cover (ADR-002 Decision 2).
/// CONTRACT: a port of <c>crates/thadam-core/src/encode.rs</c>; both are checked against
/// <c>crates/thadam-core/testdata/golden-chain.json</c>. Text is a big-endian u32 byte length
/// and UTF-8 bytes; an integer is a big-endian i64; a null text or integer is the u32 marker
/// 0xFFFFFFFF (so it differs from the empty string).
/// </summary>
internal sealed class Wire
{
    private const uint NullMarker = uint.MaxValue;
    private readonly ArrayBufferWriter<byte> _buffer = new(256);

    public Wire Text(string value)
    {
        var bytes = Encoding.UTF8.GetBytes(value);
        BinaryPrimitives.WriteUInt32BigEndian(_buffer.GetSpan(4), checked((uint)bytes.Length));
        _buffer.Advance(4);
        _buffer.Write(bytes);
        return this;
    }

    public Wire Text(string? value, bool nullable) =>
        nullable && value is null ? Null() : Text(value ?? throw new ArgumentNullException(nameof(value)));

    public Wire Int(long value)
    {
        BinaryPrimitives.WriteInt64BigEndian(_buffer.GetSpan(8), value);
        _buffer.Advance(8);
        return this;
    }

    public Wire Int(long? value) => value is { } v ? Int(v) : Null();

    private Wire Null()
    {
        BinaryPrimitives.WriteUInt32BigEndian(_buffer.GetSpan(4), NullMarker);
        _buffer.Advance(4);
        return this;
    }

    /// <summary>SHA-256 of <paramref name="prevHash"/> followed by the encoded bytes.</summary>
    public byte[] Hash(ReadOnlySpan<byte> prevHash)
    {
        using var sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        sha.AppendData(prevHash);
        sha.AppendData(_buffer.WrittenSpan);
        return sha.GetHashAndReset();
    }
}
