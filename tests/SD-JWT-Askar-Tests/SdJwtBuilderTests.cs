using System.Security.Cryptography;
using aries_askar_dotnet.AriesAskar;
using aries_askar_dotnet.Models;
using Jose;
using JWT.Algorithms;
using Microsoft.IdentityModel.Tokens;
using SD_JWT;
using SD_JWT_Askar;
using Jose;
using SD_JWT.Models;

namespace SD_JWT_Askar_Tests;

public class SdJwtBuilderTests
{
    private IntPtr _keyHandle;
    
    [SetUp]
    public void Setup()
    {
        _keyHandle = KeyApi.CreateKeyAsync(KeyAlg.P256, true).GetAwaiter().GetResult();
    }

    [TearDown]
    public void TearDown()
    {
    }

    [Test]
    public void CanSignJwt()
    {
        var sdJwtBuilder = new SdJwtBuilder();

        var claim1 = new
        {
            street = "Schulstraße 12",
            city = "Frankfurt"
        };
        sdJwtBuilder.AddClaim(new Claim("address", claim1, true));

        var askarJwtAlgo = new AskarJwtAlgorithm(_keyHandle);
        sdJwtBuilder.AddAlgorithm(askarJwtAlgo);
        sdJwtBuilder.AddSecret(new []{ "secret" });

        var jwt = sdJwtBuilder.Build();
        
        Assert.That(!string.IsNullOrEmpty(jwt));
        Assert.That(jwt.Split('~').Length, Is.EqualTo(3));
    }

    [Test]
    public void CanVerifyJwt()
    {
        var sdJwtBuilder = new SdJwtBuilder();

        var claim1 = new
        {
            street = "Schulstraße 12",
            city = "Frankfurt"
        };
        sdJwtBuilder.AddClaim(new Claim("address", claim1, true));

        var askarJwtAlgo = new AskarJwtAlgorithm(_keyHandle);
        sdJwtBuilder.AddAlgorithm(askarJwtAlgo);
        sdJwtBuilder.AddSecret(new []{ "secret" });

        var jwt = sdJwtBuilder.Build();

        var sdJwtDecoder = new SdJwtDecoder(jwt);

        var jwk = KeyApi.GetJwkPublicFromKeyAsync(_keyHandle, KeyAlg.P256).GetAwaiter().GetResult();
        var key = Jwk.FromJson(jwk, new JsonMapper());
        // Todo: Find out how to convert the JsonWebKey to ECDsa

        var json = sdJwtDecoder.Verify(new ES256Algorithm(key.ECDsaKey()));

        //var json = sdJwtDecoder.Verify(new ES256Algorithm(ECDsa.Create()));
    }
}