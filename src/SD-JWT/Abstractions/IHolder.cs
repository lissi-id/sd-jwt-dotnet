using SD_JWT.Models;

namespace SD_JWT.Abstractions
{
    public interface IHolder
    {
        public SdJwtDoc ReceiveCredential(string issuedSdJwt, string? issuerJwk = null, string? validJwtIssuer = null);

        public string CreatePresentation(string issuerSignedJwt, Disclosure[] disclosures, string? keyBindingJwt = null);
    }
}