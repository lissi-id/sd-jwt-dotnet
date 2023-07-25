using System.Security.Cryptography;
using aries_askar_dotnet.AriesAskar;
using aries_askar_dotnet.Models;
using JWT.Algorithms;

namespace SD_JWT_Askar;
public class AskarJwtAlgorithm : IJwtAlgorithm
{
    private readonly IntPtr _keyHandle;
    
    public AskarJwtAlgorithm(IntPtr keyHandle)
    {
        _keyHandle = keyHandle;
    }
    
    public byte[] Sign(byte[] key, byte[] bytesToSign)
    {
        return KeyApi.SignMessageFromKeyAsync(_keyHandle, bytesToSign, SignatureType.ES256).GetAwaiter().GetResult();
    }

    public string Name => nameof(JwtAlgorithmName.ES256);
    public HashAlgorithmName HashAlgorithmName => HashAlgorithmName.SHA256;
}
