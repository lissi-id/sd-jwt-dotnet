using SD_JWT.Models;

namespace SD_JWT.Roles.Implementation;

public class Issuer : IIssuer
{
    public string Issue(List<Claim> claims, string issuerJwk)
    {
        throw new NotImplementedException();
    }
}
