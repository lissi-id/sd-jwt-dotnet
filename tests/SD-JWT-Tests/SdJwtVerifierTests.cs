using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;
using SD_JWT;
using Claim = SD_JWT.Models.Claim;

namespace SD_JWT_Tests;

public class SdJwtVerifierTests
{
    [Test]
    public void CanVerifyPresentation()
    {
        // Arrange
        var sdJwtBuilder = new SdJwtBuilder();

        var claim1 = new
        {
            street = "Schulstraße 12",
            city = "Frankfurt"
        };

        sdJwtBuilder.AddClaim(new Claim("address", claim1, true));

        using var ecDsa = ECDsa.Create();
        ecDsa.GenerateKey(ECCurve.NamedCurves.nistP256);
        ecDsa.ExportParameters(true);
        var securityKey = new ECDsaSecurityKey(ecDsa);

        var tokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = securityKey,
            ValidateIssuer = false,
            ValidateAudience = false
        };

        var jwt = sdJwtBuilder.Build();

        var sdJwtDecoder = new SdJwtDecoder(jwt);

        // Act
        var output = sdJwtDecoder.Verify(tokenValidationParameters);

        // Assert
        Assert.That(!string.IsNullOrEmpty(output));
    }
}