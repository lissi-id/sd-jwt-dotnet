using SD_JWT.Abstractions;
using SD_JWT.Models;

namespace SD_JWT
{
    public class Holder : IHolder
    {
        public string CreatePresentation(string issuerSignedJwt, Disclosure[] disclosures, string? keyBindingJwt = null)
        {
            var presentation = disclosures.Aggregate(issuerSignedJwt, (current, disclosure) => current + $"~{disclosure.Serialize()}");

            if (!string.IsNullOrEmpty(keyBindingJwt))
            {
                presentation += $"~{keyBindingJwt}";
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
    }
}