using System.Security.Cryptography;
using System.Diagnostics;
using System.Text;


namespace JA4.Benchmark;

internal static class JA_Improved
{
    /// <summary>
    /// Conservative max stack size limit
    /// </summary>
    private const int MaxStackSize = 1024;

    public static string EncodeJA4Fingerprint(Span<byte> bytes, int length)
    {
        if (length < 9)
        {
            return string.Empty;
        }

        var span = bytes[..length];

        // TLS record header
        if (span[0] != 22)
        {
            return string.Empty; // not Handshake content type
        }

        int recordLength = (span[3] << 8) | span[4];
        if (recordLength + 5 > length)
        {
            return string.Empty;
        }

        // Handshake header
        if (span[5] != 0x01)
        {
            return string.Empty; // not ClientHello
        }

        int handshakeLength = (span[6] << 16) | (span[7] << 8) | span[8];
        if (handshakeLength + 9 > length)
        {
            return string.Empty;
        }

        int offset = 9;

        // Legacy version
        if (offset + 2 > length)
        {
            return string.Empty;
        }

        ushort legacyVersion = (ushort)((span[offset] << 8) | span[offset + 1]);
        offset += 2;
        ushort negotiatedVersion = legacyVersion;

        // Random
        offset += 32;
        if (offset > length)
        {
            return string.Empty;
        }

        // Session ID
        if (offset + 1 > length)
        {
            return string.Empty;
        }

        int sessionIdLength = span[offset++];
        offset += sessionIdLength;
        if (offset > length)
        {
            return string.Empty;
        }

        // Cipher suites
        if (offset + 2 > length)
        {
            return string.Empty;
        }

        int cipherBytes = (span[offset] << 8) | span[offset + 1];
        offset += 2;
        int cipherStart = offset;
        offset += cipherBytes;
        if (offset > length)
        {
            return string.Empty;
        }

        if ((cipherBytes & 1) != 0)
        {
            return string.Empty;
        }

        // Compression methods
        if (offset + 1 > length)
        {
            return string.Empty;
        }

        int compressionLen = span[offset++];
        offset += compressionLen;
        if (offset > length)
        {
            return string.Empty;
        }

        // Extensions
        if (offset + 2 > length)
        {
            return string.Empty;
        }

        int extensionsBytes = (span[offset] << 8) | span[offset + 1];
        offset += 2;
        int extensionsStart = offset;
        int extensionsEnd = extensionsStart + extensionsBytes;
        if (extensionsEnd > length)
        {
            return string.Empty;
        }

        const int ushortByteRatio = sizeof(ushort) / sizeof(byte);    // 2

        // Decode cipher suites
        int maxCipherSuites = cipherBytes / 2;
        Debug.Assert(maxCipherSuites * ushortByteRatio <= MaxStackSize);

        Span<ushort> cipherSuites = stackalloc ushort[maxCipherSuites];
        int cipherSuitesIndex = 0;
        for (int i = 0; i + 1 < cipherBytes; i += 2)
        {
            ushort cs = (ushort)((span[cipherStart + i] << 8) | span[cipherStart + i + 1]);
            if (!IsGrease(cs))
            {
                cipherSuites[cipherSuitesIndex] = cs;
                cipherSuitesIndex++;
            }
        }

        cipherSuites = cipherSuites[..cipherSuitesIndex];

        bool hasSni = false;
        string alpnTwoChars = "00";

        const int maxStackPerSpan = MaxStackSize / ushortByteRatio / 2;

        Span<ushort> hashExtensions = stackalloc ushort[maxStackPerSpan];
        Span<ushort> signatureAlgos = stackalloc ushort[maxStackPerSpan];  // in wire order
        int hashExtensionsIndex = 0;
        int signatureAlgosIndex = 0;
        int extensionCount = 0;

        int extOffset = extensionsStart;
        while (extOffset + 4 <= extensionsEnd)
        {
            ushort extType = (ushort)((span[extOffset] << 8) | span[extOffset + 1]);
            ushort extLen = (ushort)((span[extOffset + 2] << 8) | span[extOffset + 3]);
            int extDataStart = extOffset + 4;
            int extDataEnd = extDataStart + extLen;
            if (extDataEnd > extensionsEnd)
            {
                break;
            }

            bool grease = IsGrease(extType);
            if (!grease)
            {
                extensionCount++;

                switch (extType)
                {
                    case 0x0000: // SNI
                        hasSni = true;
                        break;

                    case 0x0010: // ALPN
                        if (extLen >= 2)
                        {
                            int alpnVectorLen = (span[extDataStart] << 8) | span[extDataStart + 1];
                            int alpnPos = extDataStart + 2;
                            int alpnVectorEnd = alpnPos + alpnVectorLen;
                            if (alpnVectorEnd == extDataEnd && alpnVectorEnd <= length)
                            {
                                while (alpnPos < alpnVectorEnd)
                                {
                                    int protoLen = span[alpnPos++];
                                    if (alpnPos + protoLen > alpnVectorEnd)
                                    {
                                        break;
                                    }

                                    if (protoLen == 2 && IsGrease((ushort)((span[alpnPos] << 8) | span[alpnPos + 1])))
                                    {
                                        alpnPos += protoLen;
                                        continue;
                                    }

                                    if (protoLen > 0)
                                    {
                                        char first = ConvertAlpnChar((char)span[alpnPos]);
                                        char last = ConvertAlpnChar((char)span[alpnPos + protoLen - 1]);
                                        if (protoLen == 1)
                                        {
                                            last = first;
                                        }

                                        alpnTwoChars = new string(new[] { first, last });
                                    }

                                    break;
                                }
                            }
                        }

                        break;

                    case 0x002b: // supported_versions
                        hashExtensions[hashExtensionsIndex++] = extType;
                        if (extLen >= 1)
                        {
                            int verCountBytes = span[extDataStart];
                            int pos = extDataStart + 1;
                            if ((verCountBytes & 1) == 0 && pos + verCountBytes == extDataEnd)
                            {
                                ushort maxVer = 0;
                                while (verCountBytes > 0)
                                {
                                    ushort v = (ushort)((span[pos] << 8) | span[pos + 1]);
                                    pos += 2;
                                    verCountBytes -= 2;
                                    if (IsGrease(v))
                                    {
                                        continue;
                                    }

                                    if (GetTlsVersionCode(v) != "00" && v > maxVer)
                                    {
                                        maxVer = v;
                                    }
                                }

                                if (maxVer != 0)
                                {
                                    negotiatedVersion = maxVer;
                                }
                            }
                        }

                        break;

                    case 0x000d: // signature_algorithms
                        hashExtensions[hashExtensionsIndex++] = extType;
                        if (extLen >= 2)
                        {
                            int sigBytes = (span[extDataStart] << 8) | span[extDataStart + 1];
                            int pos = extDataStart + 2;
                            if ((sigBytes & 1) == 0 && pos + sigBytes == extDataEnd)
                            {
                                while (sigBytes > 0)
                                {
                                    ushort algo = (ushort)((span[pos] << 8) | span[pos + 1]);
                                    pos += 2;
                                    sigBytes -= 2;
                                    if (IsGrease(algo))
                                    {
                                        continue;
                                    }

                                    signatureAlgos[signatureAlgosIndex++] = algo;
                                }
                            }
                        }

                        break;

                    default:
                        hashExtensions[hashExtensionsIndex++] = extType;
                        break;
                }
            }

            extOffset = extDataEnd;
        }

        hashExtensions = hashExtensions[..hashExtensionsIndex];
        signatureAlgos = signatureAlgos[..signatureAlgosIndex];

        string cipherHash = HashListForJa4(cipherSuites, sort: true);
        string extensionHash = HashExtensionsForJa4(hashExtensions, signatureAlgos);

        const char transport = 't';
        string versionCode = GetTlsVersionCode(negotiatedVersion);
        char sniTag = hasSni ? 'd' : 'i';
        string cipherCountStr = TwoDigitDecimal(cipherSuites.Length);
        string extCountStr = TwoDigitDecimal(extensionCount);

        return string.Create(
            36,
            (transport, versionCode, sniTag, cipherCountStr, extCountStr, alpnTwoChars, cipherHash, extensionHash),
            static (dst, s) =>
            {
                int p = 0;
                dst[p++] = s.transport;
                s.versionCode.AsSpan().CopyTo(dst[p..]);
                p += 2;
                dst[p++] = s.sniTag;
                s.cipherCountStr.AsSpan().CopyTo(dst[p..]);
                p += 2;
                s.extCountStr.AsSpan().CopyTo(dst[p..]);
                p += 2;
                s.alpnTwoChars.AsSpan().CopyTo(dst[p..]);
                p += 2;
                dst[p++] = '_';
                s.cipherHash.AsSpan().CopyTo(dst[p..]);
                p += 12;
                dst[p++] = '_';
                s.extensionHash.AsSpan().CopyTo(dst[p..]);
                p += 12;
            });

        // Local helpers

        static string HashListForJa4(Span<ushort> values, bool sort)
        {
            if (values.Length == 0)
            {
                return new string('0', 12);
            }

            if (sort)
            {
                values.Sort();
            }

            var sb = new StringBuilder((values.Length * 5) - 1);
            for (int i = 0; i < values.Length; i++)
            {
                if (i > 0)
                {
                    sb.Append(',');
                }

                sb.Append(values[i].ToString("x4"));
            }

            return Sha256First12(sb.ToString());
        }

        static string HashExtensionsForJa4(Span<ushort> extensions, Span<ushort> sigAlgos)
        {
            if (extensions.Length == 0 && sigAlgos.Length == 0)
            {
                return new string('0', 12);
            }

            extensions.Sort();

            int baseLen = extensions.Length == 0 ? 0 : ((extensions.Length * 5) - 1);
            int sigLen = sigAlgos.Length == 0 ? 0 : (1 + (sigAlgos.Length * 5) - 1);
            var sb = new StringBuilder(baseLen + sigLen);

            for (int i = 0; i < extensions.Length; i++)
            {
                if (i > 0)
                {
                    sb.Append(',');
                }

                sb.Append(extensions[i].ToString("x4"));
            }

            if (sigAlgos.Length > 0)
            {
                sb.Append('_');
                for (int i = 0; i < sigAlgos.Length; i++)
                {
                    if (i > 0)
                    {
                        sb.Append(',');
                    }

                    sb.Append(sigAlgos[i].ToString("x4"));
                }
            }

            return Sha256First12(sb.ToString());
        }

        static string Sha256First12(string input)
        {
            Span<byte> hash = stackalloc byte[32];
            SHA256.HashData(Encoding.ASCII.GetBytes(input), hash);
            Span<char> chars = stackalloc char[12];
            for (int i = 0; i < 6; i++)
            {
                byte b = hash[i];
                chars[i * 2] = (char)((b >> 4) < 10 ? '0' + (b >> 4) : 'a' + ((b >> 4) - 10));
                chars[i * 2 + 1] = (char)((b & 0xF) < 10 ? '0' + (b & 0xF) : 'a' + ((b & 0xF) - 10));
            }

            return new string(chars);
        }

        static bool IsGrease(ushort v) =>
            v is 0x0A0A or 0x1A1A or 0x2A2A or 0x3A3A or 0x4A4A or 0x5A5A or 0x6A6A or 0x7A7A
            or 0x8A8A or 0x9A9A or 0xAAAA or 0xBABA or 0xCACA or 0xDADA or 0xEAEA or 0xFAFA;

        static string GetTlsVersionCode(ushort version) => version switch
        {
            0x0304 => "13",
            0x0303 => "12",
            0x0302 => "11",
            0x0301 => "10",
            _ => "00"
        };

        static string TwoDigitDecimal(int v)
        {
            if (v < 0)
            {
                v = 0;
            }

            if (v > 99)
            {
                v = 99;
            }

            return v < 10 ? "0" + v.ToString() : v.ToString("00");
        }

        static char ConvertAlpnChar(char c)
        {
            if (c is >= 'A' and <= 'Z')
            {
                return (char)(c - 'A' + 'a');
            }

            if (c is >= 'a' and <= 'z')
            {
                return c;
            }

            if (c is >= '0' and <= '9')
            {
                return c;
            }

            return '0';
        }
    }
}
