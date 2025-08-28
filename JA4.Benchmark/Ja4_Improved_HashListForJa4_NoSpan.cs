using System.Buffers;
using System.Globalization;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;

namespace JA4.Benchmark;

internal static class Ja4_Improved_HashListForJa4_NoSpan
{
    // Record and message types
    private const byte TlsHandshakeRecordType = 22;
    private const byte TlsClientHelloType = 0x01;

    // Minimum lengths and sizes
    private const int MinTlsRecordLength = 9;
    private const int HashSize = 12;
    private const int MaxTwoDigitDecimal = 99;

    // Record header offsets and sizes
    private const int RecordLengthOffset = 3;
    private const int RecordHeaderSize = 5;
    private const int HandshakeTypeOffset = 5;
    private const int HandshakeLengthOffset = 6;
    private const int HandshakeHeaderSize = 9;

    // Extension related constants
    private const int ExtensionHeaderSize = 4;

    // Extension types
    private const ushort ExtensionSni = 0x0000;
    private const ushort ExtensionAlpn = 0x0010;
    private const ushort ExtensionSupportedVersions = 0x002b;
    private const ushort ExtensionSignatureAlgorithms = 0x000d;

    // TLS/SSL versions
    private const ushort TlsVersion13 = 0x0304;
    private const ushort TlsVersion12 = 0x0303;
    private const ushort TlsVersion11 = 0x0302;
    private const ushort TlsVersion10 = 0x0301;
    private const ushort SslVersion30 = 0x0300;

    // ALPN related constants
    private const byte AlpnProtoH2Length = 0x02;
    private const byte AlpnProtoHttp11Length = 0x08;
    private const int MinH2TokenLength = 2;
    private const int MinHttp11TokenLength = 8;

    // Offsets
    private const int TlsVersionLength = 2;
    private const int RandomDataLength = 32;

    // String constants
    private const string DefaultAlpn = "00";
    private const string AlpnH2Value = "h2";
    private const string Ssl30Code = "s3";
    private const string Tls13Code = "13";
    private const string Tls12Code = "12";
    private const string Tls11Code = "11";
    private const string Tls10Code = "10";
    private const string UnknownVersion = "00";
    private const int FingerprintLength = 36;
    private const char TransportTcp = 't';
    private const char SniTagPresent = 'd';
    private const char SniTagAbsent = 'i';
    private const char FingerprintSeparator = '_';

    // Bit manipulation constants
    private const int BitsInByte = 8;
    private const int BytesPerUshort = 2;
    private const int HexDigitsPerByte = 2;
    private const byte LowNibbleMask = 0x0F;
    private const int HashByteCount = 6;
    private const int DecimalBase = 10;

    private const int TlsVersionCodeLength = 2;
    private const int TwoDigitDecimalLength = 2;

    // ALPN token patterns
    private static readonly byte[] _http11Pattern = "http/1.1"u8.ToArray();
    private static readonly byte[] _h2Pattern = "h2"u8.ToArray();

    public static string EncodeJa4Fingerprint(ReadOnlySequence<byte> sequence)
    {
        if (sequence.IsSingleSegment)
        {
            return EncodeJa4Fingerprint(sequence.First.Span, sequence.First.Length);
        }

        var length = (int)sequence.Length;

        byte[] bytes = ArrayPool<byte>.Shared.Rent(length);

        try
        {
            sequence.CopyTo(bytes);
            return EncodeJa4Fingerprint(bytes, length);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(bytes);
        }
    }

    public static string EncodeJa4Fingerprint(ReadOnlySpan<byte> bytes, int length)
    {
        if (length < MinTlsRecordLength)
        {
            return string.Empty;
        }

        var span = bytes.Slice(0, length);

        // Validate TLS record
        if (!IsValidTlsRecord(span, length, out int extensionsStart, out int extensionsEnd,
            out int cipherStart, out int cipherBytes, out ushort negotiatedVersion))
        {
            return string.Empty;
        }

        // Process ciphersuites
        var cipherSuites = ExtractCipherSuites(span, cipherStart, cipherBytes);

        // Process extensions
        var extensionInfo = ProcessExtensions(span, extensionsStart, extensionsEnd, ref negotiatedVersion);
        bool hasSni = extensionInfo.HasSni;
        string alpnTwoChars = extensionInfo.AlpnValue;
        var hashExtensions = extensionInfo.HashExtensions;
        var signatureAlgos = extensionInfo.SignatureAlgorithms;
        int extensionCount = extensionInfo.ExtensionCount;

        if (alpnTwoChars == DefaultAlpn)
        {
            alpnTwoChars = TryScanAlpnToken(span) ?? DefaultAlpn;
        }

        // Generate hashes and build fingerprint
        return BuildFingerprint(
            cipherSuites,
            hashExtensions,
            signatureAlgos,
            negotiatedVersion,
            hasSni,
            alpnTwoChars,
            extensionCount);
    }

    /// <summary>
    /// See IsGrease_Optimization test for clarity.
    /// </summary>
    internal static bool IsGrease(ushort v)
    {
        // Grease values are 0x0A0A, 0x1A1A, ..., 0xFAFA
        // Pattern: high byte == low byte and low nibble is 0xA.
        return ((v & 0x0F0F) == 0x0A0A) && ((v >> 8) == (v & 0xFF));
    }

    /// <summary>
    /// See UshortSpanToString_Optimization test for clarity
    /// </summary>
    internal static string UshortSpanToString(ReadOnlySpan<ushort> sortedValues)
    {
        // Each entry contributes "xxxx" (4 chars) and a comma, except the first.
        int len = (sortedValues.Length * 5) - 1;
        if (len <= 0)
        {
            len = 4;
        }

        string result;
        char[] rented = ArrayPool<char>.Shared.Rent(len);
        try
        {
            var chars = rented.AsSpan(0, len);
            int p = 0;
            for (int i = 0; i < sortedValues.Length; i++)
            {
                if (i > 0)
                {
                    chars[p++] = ',';
                }

                WriteHex4Lower(chars, ref p, sortedValues[i]);
            }

            result = Sha256First12FromAscii(chars);
        }
        finally
        {
            ArrayPool<char>.Shared.Return(rented);
        }

        return result;
    }


    internal static string Sha256First12(string input)
    {
        Span<byte> hash = stackalloc byte[32];
        _ = SHA256.HashData(Encoding.ASCII.GetBytes(input), hash);
        Span<char> chars = stackalloc char[HashSize];
        for (int i = 0; i < HashByteCount; i++)
        {
            byte b = hash[i];
            chars[i * HexDigitsPerByte] = HexNibble(b >> 4);
            chars[(i * HexDigitsPerByte) + 1] = HexNibble(b & LowNibbleMask);
        }

        return new string(chars);
    }

    private static bool IsValidTlsRecord(
        ReadOnlySpan<byte> span,
        int length,
        out int extensionsStart,
        out int extensionsEnd,
        out int cipherStart,
        out int cipherBytes,
        out ushort negotiatedVersion)
    {
        // Initialize out parameters
        extensionsStart = 0;
        extensionsEnd = 0;
        cipherStart = 0;
        cipherBytes = 0;
        negotiatedVersion = 0;

        // TLS record header
        if (span[0] != TlsHandshakeRecordType)
        {
            return false;
        }

        int recordLength = (span[RecordLengthOffset] << BitsInByte) | span[RecordLengthOffset + 1];
        if (recordLength + RecordHeaderSize > length)
        {
            recordLength = length - RecordHeaderSize;
            if (recordLength <= 0)
            {
                return false;
            }
        }

        // Handshake header (ClientHello)
        if (span[HandshakeTypeOffset] != TlsClientHelloType)
        {
            return false;
        }

        int handshakeLength = (span[HandshakeLengthOffset] << (BitsInByte * 2)) |
                             (span[HandshakeLengthOffset + 1] << BitsInByte) |
                              span[HandshakeLengthOffset + 2];

        if (handshakeLength + HandshakeHeaderSize > length)
        {
            handshakeLength = length - HandshakeHeaderSize;
            if (handshakeLength <= 0)
            {
                return false;
            }
        }

        return ParseTlsClientHello(span, length, out extensionsStart, out extensionsEnd,
            out cipherStart, out cipherBytes, out negotiatedVersion);
    }

    private static bool ParseTlsClientHello(
        ReadOnlySpan<byte> span,
        int length,
        out int extensionsStart,
        out int extensionsEnd,
        out int cipherStart,
        out int cipherBytes,
        out ushort negotiatedVersion)
    {
        // Initialize out parameters
        extensionsStart = 0;
        extensionsEnd = 0;
        cipherStart = 0;
        cipherBytes = 0;
        negotiatedVersion = 0;

        int offset = HandshakeHeaderSize;

        if (offset + TlsVersionLength > length)
        {
            return false;
        }

        ushort legacyVersion = (ushort)((span[offset] << BitsInByte) | span[offset + 1]);
        offset += TlsVersionLength;
        negotiatedVersion = legacyVersion;

        // Random
        offset += RandomDataLength;
        if (offset > length)
        {
            return false;
        }

        // Session ID
        if (offset + 1 > length)
        {
            return false;
        }

        int sessionIdLen = span[offset++];
        offset += sessionIdLen;
        if (offset > length)
        {
            return false;
        }

        // Cipher suites
        if (offset + TlsVersionLength > length)
        {
            return false;
        }

        cipherBytes = (span[offset] << BitsInByte) | span[offset + 1];
        offset += TlsVersionLength;
        cipherStart = offset;
        offset += cipherBytes;
        if (offset > length)
        {
            return false;
        }

        if ((cipherBytes & 1) != 0)
        {
            return false;
        }

        // Compression methods
        if (offset + 1 > length)
        {
            return false;
        }

        int compLen = span[offset++];
        offset += compLen;
        if (offset > length)
        {
            return false;
        }

        // Extensions block
        if (offset + TlsVersionLength > length)
        {
            return false;
        }

        int declaredExtensionsBytes = (span[offset] << BitsInByte) | span[offset + 1];
        offset += TlsVersionLength;
        extensionsStart = offset;
        extensionsEnd = extensionsStart + declaredExtensionsBytes;

        if (extensionsEnd > length)
        {
            // Truncated extensions length; clamp
            extensionsEnd = length;
            declaredExtensionsBytes = extensionsEnd - extensionsStart;
            if (declaredExtensionsBytes < 0)
            {
                return false;
            }
        }

        return true;
    }

    private static Span<ushort> ExtractCipherSuites(ReadOnlySpan<byte> span, int cipherStart, int cipherBytes)
    {
        var cipherSuites = ArrayPool<ushort>.Shared.Rent(cipherBytes / BytesPerUshort);
        int cipherSuitesIndex = 0;
        for (int i = 0; i + 1 < cipherBytes; i += BytesPerUshort)
        {
            ushort cs = (ushort)((span[cipherStart + i] << BitsInByte) | span[cipherStart + i + 1]);
            if (!IsGrease(cs))
            {
                cipherSuites[cipherSuitesIndex++] = cs;
            }
        }

        return cipherSuites[0..cipherSuitesIndex].AsSpan();
    }

    private static ExtensionProcessingResult ProcessExtensions(
        ReadOnlySpan<byte> span,
        int extensionsStart,
        int extensionsEnd,
        ref ushort negotiatedVersion)
    {
        bool hasSni = false;
        string alpnTwoChars = DefaultAlpn;
        HashSet<ushort> hashExtensions = [];
        List<ushort> signatureAlgos = [];
        HashSet<ushort> distinctExtensions = [];
        int extensionCount = 0;

        // First pass - Count all extensions and parse the ones we can fully read
        int extOffset = extensionsStart;
        while (extOffset + ExtensionHeaderSize <= extensionsEnd)
        {
            ushort extType = (ushort)((span[extOffset] << BitsInByte) | span[extOffset + 1]);
            ushort extLen = (ushort)((span[extOffset + 2] << BitsInByte) | span[extOffset + 3]);
            int bodyStart = extOffset + ExtensionHeaderSize;
            int bodyEnd = bodyStart + extLen;
            bool bodyComplete = bodyEnd <= extensionsEnd;

            // Only process non-GREASE extensions
            if (!IsGrease(extType))
            {
                // Always count it
                if (distinctExtensions.Add(extType))
                {
                    extensionCount++;
                }

                // Process specific extensions if we can fully read them
                switch (extType)
                {
                    case ExtensionSni: // SNI
                        hasSni = true;
                        break;
                    case ExtensionAlpn: // ALPN
                        if (bodyComplete)
                        {
                            ParseAlpn(span, bodyStart, bodyEnd, ref alpnTwoChars);
                        }

                        break;
                    case ExtensionSupportedVersions: // supported_versions
                        if (bodyComplete)
                        {
                            ParseSupportedVersions(span, bodyStart, bodyEnd, ref negotiatedVersion);
                        }

                        _ = hashExtensions.Add(extType);
                        break;
                    case ExtensionSignatureAlgorithms: // signature_algorithms
                        if (bodyComplete)
                        {
                            ParseSignatureAlgorithms(span, bodyStart, bodyEnd, signatureAlgos);
                        }

                        _ = hashExtensions.Add(extType);
                        break;
                    default:
                        _ = hashExtensions.Add(extType);

                        break;
                }
            }

            // Move to next extension if possible
            if (!bodyComplete)
            {
                break;
            }

            extOffset = bodyEnd;
        }

        return new ExtensionProcessingResult(
            hasSni,
            alpnTwoChars,
            hashExtensions,
            signatureAlgos,
            extensionCount);
    }

    private static string BuildFingerprint(
        Span<ushort> cipherSuites,
        Span<ushort> hashExtensions,
        ReadOnlySpan<ushort> signatureAlgos,
        ushort negotiatedVersion,
        bool hasSni,
        string alpnTwoChars,
        int extensionCount)
    {
        string cipherHash = HashListForJa4(cipherSuites, sort: true);
        string extensionHash = HashExtensionsForJa4(hashExtensions, signatureAlgos);

        const char Transport = TransportTcp;
        string versionCode = GetTlsVersionCode(negotiatedVersion);
        char sniTag = hasSni ? SniTagPresent : SniTagAbsent;
        string cipherCountStr = TwoDigitDecimal(cipherSuites.Length);
        string extCountStr = TwoDigitDecimal(extensionCount);

        return string.Create(
            FingerprintLength,
            (Transport, versionCode, sniTag, cipherCountStr, extCountStr, alpnTwoChars, cipherHash, extensionHash),
            static (dst, s) =>
            {
                int p = 0;
                dst[p++] = s.Transport;
                s.versionCode.AsSpan().CopyTo(dst[p..]);
                p += TlsVersionCodeLength;
                dst[p++] = s.sniTag;
                s.cipherCountStr.AsSpan().CopyTo(dst[p..]);
                p += TwoDigitDecimalLength;
                s.extCountStr.AsSpan().CopyTo(dst[p..]);
                p += TwoDigitDecimalLength;
                s.alpnTwoChars.AsSpan().CopyTo(dst[p..]);
                p += TwoDigitDecimalLength;
                dst[p++] = FingerprintSeparator;
                s.cipherHash.AsSpan().CopyTo(dst[p..]);
                p += HashSize;
                dst[p++] = FingerprintSeparator;
                s.extensionHash.AsSpan().CopyTo(dst[p..]);
            });
    }

    private static void ParseAlpn(ReadOnlySpan<byte> span, int start, int end, ref string alpnTwoChars)
    {
        if (end - start < TlsVersionLength)
        {
            return;
        }

        int listLen = (span[start] << BitsInByte) | span[start + 1];
        int pos = start + TlsVersionLength;
        int listEnd = pos + listLen;
        if (listEnd > end)
        {
            return;
        }

        while (pos < listEnd)
        {
            int protoLen = span[pos++];
            if (protoLen <= 0 || pos + protoLen > listEnd)
            {
                break;
            }

            // Skip GREASE values in ALPN
            if (protoLen == TlsVersionLength && IsGrease((ushort)((span[pos] << BitsInByte) | span[pos + 1])))
            {
                pos += TlsVersionLength;
                continue;
            }

            byte firstRaw = span[pos];
            byte lastRaw = span[pos + protoLen - 1];

            bool fv = IsVisibleAscii(firstRaw);
            bool lv = IsVisibleAscii(lastRaw);

            if (fv || lv)
            {
                char first = ConvertAlpnChar((char)firstRaw);
                char last = ConvertAlpnChar((char)lastRaw);
                if (protoLen == 1)
                {
                    last = first;
                }

                alpnTwoChars = new string(new[] { first, last });
            }
            else
            {
                char first = NibbleToHexChar(firstRaw >> 4);
                char last = NibbleToHexChar(lastRaw & LowNibbleMask);
                alpnTwoChars = new string(new[] { first, last });
            }

            break;
        }
    }

    private static void ParseSupportedVersions(ReadOnlySpan<byte> span, int start, int end, ref ushort negotiatedVersion)
    {
        if (end - start < 1)
        {
            return;
        }

        int verBytes = span[start];
        int pos = start + 1;
        if ((verBytes & 1) != 0)
        {
            return;
        }

        if (pos + verBytes > end)
        {
            return;
        }

        ushort max = 0;
        int remaining = verBytes;
        while (remaining > 0 && pos + 1 < end)
        {
            ushort v = (ushort)((span[pos] << BitsInByte) | span[pos + 1]);
            pos += TlsVersionLength;
            remaining -= TlsVersionLength;
            if (IsGrease(v))
            {
                continue;
            }

            if (GetTlsVersionCode(v) != UnknownVersion && v > max)
            {
                max = v;
            }
        }

        if (max != 0)
        {
            negotiatedVersion = max;
        }
    }

    private static void ParseSignatureAlgorithms(ReadOnlySpan<byte> span, int start, int end, List<ushort> signatureAlgos)
    {
        if (end - start < TlsVersionLength)
        {
            return;
        }

        int listBytes = (span[start] << BitsInByte) | span[start + 1];
        int pos = start + TlsVersionLength;
        if ((listBytes & 1) != 0)
        {
            return;
        }

        if (pos + listBytes > end)
        {
            return;
        }

        int remaining = listBytes;
        while (remaining > 0 && pos + 1 < end)
        {
            ushort algo = (ushort)((span[pos] << BitsInByte) | span[pos + 1]);
            pos += TlsVersionLength;
            remaining -= TlsVersionLength;
            if (IsGrease(algo))
            {
                continue;
            }

            signatureAlgos.Add(algo);
        }
    }

    private static string HashListForJa4(Span<ushort> values, bool sort)
    {
        if (values.Length == 0)
        {
            return new string('0', HashSize);
        }

        if (sort)
        {
            values.Sort();
        }

        return UshortSpanToString(values);

    }

    // Writes the 4 lowercase-hex chars for a ushort into 'dst' starting at current index 'p'.
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void WriteHex4Lower(Span<char> dst, ref int p, ushort v)
    {
        dst[p++] = HexNibble((v >> 12) & 0xF);
        dst[p++] = HexNibble((v >> 8) & 0xF);
        dst[p++] = HexNibble((v >> 4) & 0xF);
        dst[p++] = HexNibble(v & 0xF);
    }

    private static string Sha256First12FromAscii(ReadOnlySpan<char> ascii)
    {
        // Convert ASCII chars to bytes without allocating strings/encoders.
        int len = ascii.Length;

        Span<byte> hash = stackalloc byte[32];
        if (len <= 256)
        {
            Span<byte> bytes = stackalloc byte[len];

            for (int i = 0; i < len; i++)
            {
                bytes[i] = (byte)ascii[i];
            }

            _ = SHA256.HashData(bytes, hash);
        }
        else
        {
            byte[] rented = ArrayPool<byte>.Shared.Rent(len);
            try
            {
                var bytes = rented.AsSpan(0, len);

                for (int i = 0; i < len; i++)
                {
                    bytes[i] = (byte)ascii[i];
                }

                _ = SHA256.HashData(bytes, hash);
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(rented);
            }
        }

        Span<char> chars = stackalloc char[HashSize];
        for (int i = 0; i < HashByteCount; i++)
        {
            byte b = hash[i];
            chars[i * HexDigitsPerByte] = HexNibble(b >> 4);
            chars[(i * HexDigitsPerByte) + 1] = HexNibble(b & LowNibbleMask);
        }

        return new string(chars);
    }

    private static string HashExtensionsForJa4(Span<ushort> extensions, ReadOnlySpan<ushort> sigAlgos)
    {
        if (extensions.Length == 0 && sigAlgos.Length == 0)
        {
            return new string('0', HashSize);
        }

        extensions.Sort();
        int baseLen = extensions.Length == 0 ? 0 : ((extensions.Length * 5) - 1);
        int sigLen = sigAlgos.Length == 0 ? 0 : (1 + (sigAlgos.Length * 5) - 1);
        var sb = new StringBuilder(baseLen + sigLen);
        for (int i = 0; i < extensions.Length; i++)
        {
            if (i > 0)
            {
                _ = sb.Append(',');
            }

            _ = sb.Append(extensions[i].ToString("x4", CultureInfo.InvariantCulture));
        }

        if (sigAlgos.Length > 0)
        {
            _ = sb.Append('_');
            for (int i = 0; i < sigAlgos.Length; i++)
            {
                if (i > 0)
                {
                    _ = sb.Append(',');
                }

                _ = sb.Append(sigAlgos[i].ToString("x4", CultureInfo.InvariantCulture));
            }
        }

        return Sha256First12(sb.ToString());
    }

    private static char HexNibble(int n)
    {
        if (n < DecimalBase)
        {
            return (char)('0' + n);
        }
        else
        {
            return (char)('a' + (n - DecimalBase));
        }
    }

    private static string GetTlsVersionCode(ushort v) =>
        v switch
        {
            TlsVersion13 => Tls13Code,
            TlsVersion12 => Tls12Code,
            TlsVersion11 => Tls11Code,
            TlsVersion10 => Tls10Code,
            SslVersion30 => Ssl30Code,
            _ => UnknownVersion
        };

    private static string TwoDigitDecimal(int v) =>
        Math.Clamp(v, 0, MaxTwoDigitDecimal).ToString("00", CultureInfo.InvariantCulture);

    private static char ConvertAlpnChar(char c) =>
        c switch
        {
            >= 'A' and <= 'Z' => (char)(c - 'A' + 'a'),
            >= 'a' and <= 'z' => c,
            >= '0' and <= '9' => c,
            _ => '0',
        };

    private static bool IsVisibleAscii(byte b)
    {
        // Check if in uppercase range
        if (b >= (byte)'A' && b <= (byte)'Z')
        {
            return true;
        }

        // Check if in lowercase range
        if (b >= (byte)'a' && b <= (byte)'z')
        {
            return true;
        }

        // Check if in digit range
        return b >= (byte)'0' && b <= (byte)'9';
    }

    private static char NibbleToHexChar(int n)
    {
        if (n < DecimalBase)
        {
            return (char)('0' + n);
        }

        return (char)('a' + (n - DecimalBase));
    }

    private static string? TryScanAlpnToken(ReadOnlySpan<byte> raw)
    {
        // Look for ALPN protocol patterns
        for (int i = 0; i < raw.Length - MinH2TokenLength; i++)
        {
            // Check for HTTP/2 pattern
            bool isH2LengthPresent = i > 0 && raw[i - 1] == AlpnProtoH2Length;
            bool matchesH2Pattern = i + MinH2TokenLength <= raw.Length &&
                MatchesPattern(raw.Slice(i, MinH2TokenLength), _h2Pattern);

            if ((isH2LengthPresent || raw[i] == AlpnProtoH2Length) && matchesH2Pattern)
            {
                return AlpnH2Value;
            }

            // Check for HTTP/1.1 pattern if we have enough bytes
            if (i + MinHttp11TokenLength <= raw.Length)
            {
                bool isHttp11LengthPresent = i > 0 && raw[i - 1] == AlpnProtoHttp11Length;
                bool matchesHttp11Pattern = MatchesPattern(raw.Slice(i, MinHttp11TokenLength), _http11Pattern);

                if ((isHttp11LengthPresent || raw[i] == AlpnProtoHttp11Length) && matchesHttp11Pattern)
                {
                    return "11";
                }
            }
        }

        return null;
    }

    private static bool MatchesPattern(ReadOnlySpan<byte> data, ReadOnlySpan<byte> pattern)
    {
        if (data.Length < pattern.Length)
        {
            return false;
        }

        for (int i = 0; i < pattern.Length; i++)
        {
            if (data[i] != pattern[i])
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>
    /// Holds the results of extension processing.
    /// </summary>
    private readonly ref struct ExtensionProcessingResult
    {
        public bool HasSni { get; }
        public string AlpnValue { get; }
        public Span<ushort> HashExtensions { get; }
        public Span<ushort> SignatureAlgorithms { get; }
        public int ExtensionCount { get; }

        public ExtensionProcessingResult(bool hasSni, string alpnTwoChars, HashSet<ushort> hashExtensions, List<ushort> signatureAlgos, int extensionCount)
        {
            HasSni = hasSni;
            AlpnValue = alpnTwoChars;
            HashExtensions = hashExtensions.ToArray().AsSpan();
            ExtensionCount = extensionCount;
            SignatureAlgorithms = System.Runtime.InteropServices.CollectionsMarshal.AsSpan(signatureAlgos);
            ExtensionCount = extensionCount;
        }
    }
}
