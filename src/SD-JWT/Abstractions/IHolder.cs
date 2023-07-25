using SD_JWT.Models;

namespace SD_JWT.Abstractions;

public interface IHolder
{
    public void ReceiveCredential(string sdJwt);

    public string CreatePresentation(SdJwtDoc sdJwt, string[] holderDisclosures, string? holderKey = null, string? nonce = null, string? audience = null);
}