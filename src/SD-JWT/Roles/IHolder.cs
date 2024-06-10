using SD_JWT.Models;

namespace SD_JWT.Roles
{
    public interface IHolder
    {
        public SdJwtDoc ReceiveCredential(string issuedSdJwt, string? issuerJwk = null, string? validJwtIssuer = null);

        public PresentationFormat CreatePresentationFormat(string issuerSignedJwt, Disclosure[] disclosures);
    }
}