namespace SD_JWT.Roles;

public interface IVerifier
{
    public bool VerifyPresentation(string presentation, string issuerJwk);
}

