using SD_JWT.Models;

namespace SD_JWT.Abstractions
{
    public interface IHolder
    {
        public SdJwtDoc ReceiveCredential(string sdJwt);

        public string CreatePresentation(string issuerSignedJwt, Disclosure[] disclosures, string? keyBindingJwt = null);
    }
}