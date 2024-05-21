using SD_JWT.Models;

namespace SD_JWT.Roles;

public interface IIssuer
{
    public string Issue(List<Claim> claims, string issuerJwk);
}