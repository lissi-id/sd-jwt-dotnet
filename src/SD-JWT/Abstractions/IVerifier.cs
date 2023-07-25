using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;

namespace SD_JWT.Abstractions;

public interface IVerifier
{
    public bool VerifyPresentation(string presentation, string issuerJwk);
}

