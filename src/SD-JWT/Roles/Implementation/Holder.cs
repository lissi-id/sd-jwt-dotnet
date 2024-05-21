using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json.Linq;
using SD_JWT.Models;

namespace SD_JWT.Roles.Implementation
{
    public class Holder : IHolder
    {
        public PresentationFormat CreatePresentationFormat(string issuerSignedJwt, Disclosure[] disclosures)
        {
            var presentation = disclosures.Aggregate(issuerSignedJwt + "~", (current, disclosure) => current + $"{disclosure.Serialize()}~");
            return new PresentationFormat(presentation);
        }

        public PresentationFormat CreatePresentationFormat(SdJwtDoc sdJwtDoc, string[] disclosedPaths)
        {
            throw new NotImplementedException();
        }

        public SdJwtDoc ReceiveCredential(string issuedSdJwt, string? issuerJwk = null, string? validJwtIssuer = null)
        {
            SdJwtDoc doc = new SdJwtDoc(issuedSdJwt);
            
            if (!string.IsNullOrWhiteSpace(issuerJwk) && !string.IsNullOrWhiteSpace(validJwtIssuer))
                doc.AssertThatJwtSignatureIsValid(issuerJwk, validJwtIssuer);
            
            return new SdJwtDoc(issuedSdJwt);
        }

        private void ValidateSdJwt(string issuanceFormat, string issuerJwk, string validJwtIssuer)
        {
            var sdJwtItems = issuanceFormat.Split('~');
            if (!string.IsNullOrEmpty(sdJwtItems.Last()))
                throw new InvalidOperationException("Invalid SD-JWT - Cant contain Key Binding JWT");

            var issuerSignedJwt = sdJwtItems.First();
            IsIssuerSignedJwtValid(issuerSignedJwt, issuerJwk, validJwtIssuer);

            //TODO: Use _sd_alg to hash and verify the digests
            var securedPayload = JObject.Parse(Base64UrlEncoder.Decode(issuerSignedJwt.Split('.')[1]));
            var disclosures = sdJwtItems[1..^1].Select(Disclosure.Deserialize).ToList();
            securedPayload.SelectToken("$._sd_alg")?.Parent?.Remove();
            var unsecuredPayload = ValidateDisclosures(securedPayload, disclosures, new List<string>());

            if (!VerifyJwtValidityClaims(unsecuredPayload))
                throw new InvalidOperationException("Invalid SD-JWT - Necessary Validation Claims missing");
        }

        private bool VerifyJwtValidityClaims(JObject plainSdJwt)
        {
            var iss = plainSdJwt.SelectToken("iss");
            var vct = plainSdJwt.SelectToken("vct");
            var iat = plainSdJwt.SelectToken("iat");
            
            return !(iss == null | iat == null | vct == null);
        }

        private JObject ValidateDisclosures(JObject securedPayload, List<Disclosure> disclosures, List<string> processedDigests)
        {
            var embeddedSdDigests = securedPayload.SelectTokens("$.._sd").FirstOrDefault();
            if (embeddedSdDigests != null)
            {
                foreach (var sdDigest in embeddedSdDigests.ToList())
                {
                    if (processedDigests.Any(processedDigest => processedDigest == sdDigest.ToString()))
                        throw new InvalidOperationException("Invalid SD-JWT - Digests must be unique");
                    processedDigests.Add(sdDigest.ToString());
                    
                    var matchingDisclosure = disclosures.Find(disclosure => disclosure.GetDigest() == sdDigest.ToString());
                    if (matchingDisclosure == null)
                        continue;
                    
                    if (matchingDisclosure.Name == "_sd" | matchingDisclosure.Name == "...")
                        throw new InvalidOperationException("Invalid SD-JWT - _sd and ... are reserved claim names");

                    var parent = embeddedSdDigests.Parent?.Parent;
                    if (parent == null || parent.SelectToken(matchingDisclosure.Name) != null)
                        throw new InvalidOperationException("Invalid SD-JWT - Disclosure name already exists in the payload");
                
                    parent.Add(new JProperty(matchingDisclosure.Name, matchingDisclosure.Value));
                }

                embeddedSdDigests.Parent?.Remove();
                ValidateDisclosures(securedPayload, disclosures, processedDigests);
            }

            var embeddedArrayDigests = securedPayload.SelectTokens("$..['...']").ToList();
            if (embeddedArrayDigests.Count > 0)
            {
                foreach (var arrayDigests in embeddedArrayDigests)
                {
                    if (processedDigests.Any(processedDigest => processedDigest == arrayDigests.ToString()))
                        throw new InvalidOperationException("Invalid SD-JWT - Digests must be unique");
                    processedDigests.Add(arrayDigests.ToString());
                    
                    var matchingDisclosure = disclosures.Find(disclosure => disclosure.GetDigest() == arrayDigests.ToString());

                    if (matchingDisclosure == null)
                        arrayDigests.Parent?.Parent?.Remove();
                    else
                        arrayDigests.Parent?.Parent?.Replace(matchingDisclosure.Value.ToString());
                }
            
                ValidateDisclosures(securedPayload, disclosures, processedDigests);
            }
            
            return securedPayload;
        }

        private void IsIssuerSignedJwtValid(string issuanceFormat, string issuerJwk, string expectedIssuer)
        {
            var jwtHandler = new JwtSecurityTokenHandler();
            
            var jwtPayload = Base64UrlEncoder.Decode(issuanceFormat.Split('.')[1]);
            var exp = JObject.Parse(jwtPayload).SelectToken("exp");
            
            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidIssuer = expectedIssuer,
                ValidateAudience = false,
                ValidateLifetime =  exp != null,
                ValidateIssuerSigningKey = true,
                ValidTypes = new string[] {"vc+sd-jwt"},
                ValidAlgorithms = new string[] {"ES256"},
                IssuerSigningKey = JsonWebKey.Create(issuerJwk)
            };

            try
            {
                jwtHandler.ValidateToken(issuanceFormat, validationParameters, out var result);
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException("Invalid SD-JWT - Issuer Signed Jwt invalid", ex);
            }
        }
    }
}