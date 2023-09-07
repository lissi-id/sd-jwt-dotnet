using System.Security.Cryptography;
using System.Text;
using Newtonsoft.Json;
using SD_JWT.Abstractions;
using SD_JWT.Models;

namespace SD_JWT;

public class Holder : IHolder
{
    public string CreatePresentation(SdJwtDoc sdJwt, string[] holderDisclosures, string? holderKey = null,
        string? nonce = null, string? audience = null)
    {
        /*
            1. Decide which Disclosures to release to the Verifier, obtaining proper End-User consent if necessary.
            2. If Holder Binding is required, create a Holder Binding JWT.
            3. Create the Combined Format for Presentation, including the selected Disclosures and, if applicable, the Holder Binding JWT.
            4. Send the Presentation to the Verifier.
        */
        var presentation = sdJwt.EncodedJwt;

        foreach (var disclosure in sdJwt.Disclosures)
            if (holderDisclosures.Contains(disclosure.GetDigest()))
                presentation += $"~{disclosure.Serialize()}";

        // Add holder binding
        presentation += "~";

        if (holderKey != null && nonce != null && audience != null)
        {
            var payload = new Dictionary<string, object>
            {
                { "nonce", nonce },
                { "aud", audience },
                { "iat", DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString() }
            };

            var confirmationJwt = CreateJwt(payload, holderKey);
            presentation += confirmationJwt;
        }

        return presentation;
    }

    public SdJwtDoc ReceiveCredential(string sdJwt)
    {
        /*
            1. Separate the SD-JWT and the Disclosures in the Combined Format for Issuance.
            2. Hash all of the Disclosures separately.
            3. Find the places in the SD-JWT where the digests of the Disclosures are included.
               If any of the digests cannot be found in the SD-JWT, the Holder MUST reject the SD-JWT.
            4. Decode Disclosures and obtain plaintext of the claim values.
         */
        return new SdJwtDoc(sdJwt);
    }

    private static string CreateJwt(Dictionary<string, object> payload, string holderKey)
    {
        var header = new
        {
            alg = "ES256",
            typ = "openid4vci-proof+jwt"
        };

        var headerBytes = Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(header));
        var payloadBytes = Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(payload));

        var headerBase64 = Convert.ToBase64String(headerBytes);
        var payloadBase64 = Convert.ToBase64String(payloadBytes);

        var signatureInput = $"{headerBase64}.{payloadBase64}";
        var signatureInputBytes = Encoding.UTF8.GetBytes(signatureInput);

        byte[] signatureBytes;
        using (var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256))
        {
            if (ecdsa == null)
                throw new InvalidOperationException("ECDSA cannot be null");

            signatureBytes = ecdsa.SignData(signatureInputBytes, HashAlgorithmName.SHA256);
        }
    
        var signatureBase64 = Convert.ToBase64String(signatureBytes);

        return $"{headerBase64}.{payloadBase64}.{signatureBase64}";
    }
}