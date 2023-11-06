using System.Collections.Immutable;

namespace SD_JWT.Models;

public class SdJwtDoc
{
    public ImmutableList<Disclosure> Disclosures { get; }
    
    public string EncodedIssuerSignedJwt { get; }

    public SdJwtDoc(string issuedSdJwt)
    {
        var sdJwtItems = issuedSdJwt.Split('~');
        sdJwtItems = Array.FindAll(sdJwtItems, item => !string.IsNullOrEmpty(item));

        EncodedIssuerSignedJwt = sdJwtItems.First();
        Disclosures = sdJwtItems[1..].Select(Disclosure.Deserialize).ToImmutableList();
    }
}