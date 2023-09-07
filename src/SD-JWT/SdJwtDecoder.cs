using System.IdentityModel.Tokens.Jwt;
using JWT.Algorithms;
using JWT.Builder;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json.Linq;
using SD_JWT.Models;

namespace SD_JWT;

public class SdJwtDecoder
{
    public SdJwtDecoder(string presentation)
    {
        var ps = presentation.Split('~');

        _jwt = ps.First();
        _json = Base64UrlEncoder.Decode(_jwt.Split('.')[1]);
        _disclosures = ps[1..^1].Select(Disclosure.Deserialize).ToList();
    }

    private readonly List<Disclosure> _disclosures;
    private readonly string _json;
    private readonly string _jwt;

    public override string ToString()
    {
        return _json;
    }

    public string Verify(IJwtAlgorithm algorithm)
    {
        var json = JwtBuilder.Create()
            .MustVerifySignature()
            .WithAlgorithm(algorithm)
            .Decode(_jwt);

        var jObject = JObject.Parse(json);
        if (jObject.ContainsKey("_sd") && jObject["_sd"] is JArray array)
            foreach (var disclosure in _disclosures)
            {
                var token = array.First(hash => hash.Value<string>() == disclosure.GetDigest());
                token.Remove();

                jObject.Add(disclosure.Name, disclosure.Value as JToken);
            }

        return jObject.ToString();
    }

    public string Verify(TokenValidationParameters tokenValidationParameters)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        tokenHandler.ValidateToken(_jwt, tokenValidationParameters, out _);

        var jObject = JObject.Parse(_json);
        if (jObject.ContainsKey("_sd") && jObject["_sd"] is JArray array)
            foreach (var disclosure in _disclosures)
            {
                var token = array.First(hash => hash.Value<string>() == disclosure.GetDigest());
                token.Remove();

                jObject.Add(disclosure.Name, disclosure.Value as JToken);
            }

        return jObject.ToString();
    }
}