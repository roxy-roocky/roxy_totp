using System;
using System.Buffers.Binary;
using System.ComponentModel.DataAnnotations;
using System.Diagnostics.CodeAnalysis;
using System.Linq.Expressions;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Options;
using roxy_totp.Models;
using Sidio.Text.Base32;

namespace roxy_totp;

public class TOTP
{
    public static async Task<string> GenerateURIAsync(GenerationRequest request)
    {
        // Validate request
        ArgumentOutOfRangeException.ThrowIfLessThan(request.Length, 128);
        if(request.Length % 8 != 0) 
            throw new ArgumentException("Length must be a multiple of 8", nameof(request));

        ArgumentOutOfRangeException.ThrowIfLessThan(request.Digits, 6);     
        ArgumentOutOfRangeException.ThrowIfGreaterThan(request.Digits, 8);

        ArgumentException.ThrowIfNullOrWhiteSpace(request.Label);
        if(request.Label.Contains(':')) 
            throw new ArgumentException("Label must contain no char ':'", nameof(request));

        if(request.Issuer is not null && request.Issuer.Contains(':')) 
            throw new ArgumentException("Issuer must contain no char ':'", nameof(request));

        // Generate secret
        var secret = RandomNumberGenerator.GetBytes(request.Length / 8);

        // Generate URI parameters
        var label = string.IsNullOrWhiteSpace(request.Issuer) ? request.Label : $"{request.Issuer}:{request.Label}";
        var secretEncoded = Base32.Encode(secret);

        var dataBuilder = new StringBuilder();
        if(!string.IsNullOrWhiteSpace(request.Issuer))
        {
            dataBuilder.Append("issuer=");  dataBuilder.Append(request.Issuer); dataBuilder.Append('&');
        }

        dataBuilder.Append("secret=");      dataBuilder.Append(Uri.EscapeDataString(secretEncoded));    dataBuilder.Append('&');
        dataBuilder.Append("period=");      dataBuilder.Append(request.PeriodSeconds);                  dataBuilder.Append('&');
        dataBuilder.Append("algorithm=");   dataBuilder.Append(request.Algorithm.ToString());

        return $"otpauth://totp/{label}?{dataBuilder}";
    }

    private static readonly long[] pow10 = [
        1,
        10,
        100,
        1000,
        10_000,
        100_000,
        1_000_000,
        10_000_000,
        100_000_000,
        1_000_000_000,
    ];

    public static Dictionary<long, string> GenerateCodes(CodeRequest request)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(request.PeriodsTolerance, nameof(request));
        ArgumentOutOfRangeException.ThrowIfLessThan(request.PeriodSeconds, 15, nameof(request));

        ArgumentOutOfRangeException.ThrowIfLessThan(request.Digits, 6);     
        ArgumentOutOfRangeException.ThrowIfGreaterThan(request.Digits, 8);

        var t = (request.Time is null ? DateTimeOffset.UtcNow.ToUnixTimeSeconds() : request.Time.Value) / request.PeriodSeconds;

        var key = Base32.Decode(request.Secret);

        HMAC hmacMethod = request.Algorithm switch
        {
            Models.HashAlgorithm.SHA512 => new HMACSHA512(key),
            Models.HashAlgorithm.SHA256 => new HMACSHA256(key),
            Models.HashAlgorithm.SHA1 => new HMACSHA1(key),
            _ => throw new Exception("Wrong hash algorithm")
        };

        Dictionary<long, string> dict = [];
        
        Span<byte> span = stackalloc byte[8];

        for(int i = -request.PeriodsTolerance; i <= request.PeriodsTolerance; i++)
        {
            BinaryPrimitives.WriteInt64BigEndian(span, t - i);

            var hmac = hmacMethod.ComputeHash(span.ToArray());
            var o = hmac.Last() % 16;
            byte[] slice = [..new ReadOnlySpan<byte>(hmac, o, 4)];
            slice[0] = (byte)(slice[0] % 128);

            var code = (long)BinaryPrimitives.ReadInt32BigEndian(slice) % pow10[request.Digits];

            dict.Add(t - i, code.ToString().PadLeft(request.Digits, '0'));
        }

        return dict;
    }
    
}
