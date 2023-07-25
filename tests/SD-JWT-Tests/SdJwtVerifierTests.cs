using System.Security.Cryptography;
using JWT.Algorithms;
using SD_JWT;
using SD_JWT.Models;

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

        using ECDsa ecDsa = ECDsa.Create();
        var alg = new ES256Algorithm(ecDsa, ecDsa);
        
        sdJwtBuilder.AddAlgorithm(alg);

        var jwt = sdJwtBuilder.Build();

        var sdJwtDecoder = new SdJwtDecoder(jwt);
        
        // Act
        var output = sdJwtDecoder.Verify(alg);
        
        // Assert
        Assert.That(!string.IsNullOrEmpty(output));
    }
}