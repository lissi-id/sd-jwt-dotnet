using System.Collections.Immutable;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json.Linq;

namespace SD_JWT.Models;

public class SdJwtDoc
{
    public ImmutableList<Disclosure> Disclosures { get; }
    
    public string EncodedIssuerSignedJwt { get; }

    public SdJwtDoc(string issuedSdJwt)
    {
        var items = issuedSdJwt.Split('~');
        items = Array.FindAll(items, item => !string.IsNullOrEmpty(item));

        EncodedIssuerSignedJwt = items.First();
        _jwtPayload = Base64UrlEncoder.Decode(EncodedIssuerSignedJwt.Split('.')[1]);
        Disclosures = items[1..].Select(Disclosure.Deserialize).ToImmutableList();

        Verify();
    }

    private readonly string _jwtPayload;

    private List<JProperty> FindPropertiesByName(JToken token, string propertyName)
    {
        var matchingProperties = new List<JProperty>();

        if (token.Type == JTokenType.Object)
        {
            foreach (var property in token.Children<JProperty>())
            {
                if (property.Name == propertyName)
                {
                    matchingProperties.Add(property);
                }

                matchingProperties.AddRange(FindPropertiesByName(property.Value, propertyName));
            }
        }
        else if (token.Type == JTokenType.Array)
        {
            foreach (var child in token.Children())
            {
                matchingProperties.AddRange(FindPropertiesByName(child, propertyName));
            }
        }

        return matchingProperties;
    }

    private void Verify()
    {
        var jObject = JObject.Parse(_jwtPayload);
        var hashedDisclosures = Disclosures.ToDictionary(x => x.GetDigest());

        var sdProperties = FindPropertiesByName(jObject, "_sd");

        foreach (var sdProperty in sdProperties)
        {
            if (sdProperty.Value is JArray array)
            {
                foreach (var jToken in array)
                {
                    var hash = jToken.Value<string>()!;
                    if (hashedDisclosures.Keys.Contains(hash))
                    {
                        var disclosure = hashedDisclosures[hash];
                        var newJProperty = new JProperty("~~sd~~" + disclosure.Name, disclosure.Value);
                        sdProperty.Parent!.Add(newJProperty);

                        hashedDisclosures.Remove(hash);
                    }
                }
            }
        }

        if (hashedDisclosures.Count != 0)
        {
            throw new Exception("Invalid sd jwt");
        }
    }
}