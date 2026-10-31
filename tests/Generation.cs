using System.Text;
using Sidio.Text.Base32;

namespace tests;

public class Generation(ITestOutputHelper output)
{
    [Fact]
    public async Task TestURLNoIssuer()
    {
        var uri = await roxy_totp.TOTP.GenerateURIAsync(new roxy_totp.Models.GenerationRequest
        {
            Label = "RoxyTest"
        });
        output.WriteLine(uri);
        Assert.True(true);
    }

    [Fact]
    public async Task TestURLWithIssuer()
    {
        var uri = await roxy_totp.TOTP.GenerateURIAsync(new roxy_totp.Models.GenerationRequest
        {
            Label = "RoxyTest",
            Issuer = "Roxane"
        });
        output.WriteLine(uri);
        Assert.True(true);
    }

    [Theory]
    // RFC 6238 Tests
    [InlineData("12345678901234567890", false, 59, 8, roxy_totp.Models.HashAlgorithm.SHA1, "94287082")]
    [InlineData("12345678901234567890123456789012", false, 59, 8, roxy_totp.Models.HashAlgorithm.SHA256, "46119246")]
    [InlineData("1234567890123456789012345678901234567890123456789012345678901234", false, 59, 8, roxy_totp.Models.HashAlgorithm.SHA512, "90693936")]
    // Personal test
    [InlineData("XDH4DIAKI6I5NKV2I6AXDJNP65FIC7YH", true, 1793442972, 6, roxy_totp.Models.HashAlgorithm.SHA1,  "294008")]
    public async Task TestCodes(string secret, bool encoded, long timestamp, int digits, roxy_totp.Models.HashAlgorithm hash, string code)
    {
        var secretProcessed = encoded ? secret : Base32.Encode(ASCIIEncoding.ASCII.GetBytes(secret));
        var codes = roxy_totp.TOTP.GenerateCodes(new roxy_totp.Models.CodeRequest
        {
            Secret = secretProcessed,
            Time = timestamp,
            Digits = digits,
            Algorithm = hash
        });

        Assert.True(codes.First().Value == code);
    }
}
