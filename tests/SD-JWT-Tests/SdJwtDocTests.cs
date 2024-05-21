using Newtonsoft.Json.Linq;
using SD_JWT_Tests.Examples;
using SD_JWT.Models;

namespace SD_JWT_Tests;

public class SdJwtDocTests
{
    [TestCase(typeof(Example1))]
    [TestCase(typeof(Example4A))]
    [Test]
    public void CanParseExampleSdJwt(Type example)
    {
        var input = (BaseExample)Activator.CreateInstance(example)!;
        var doc = new SdJwtDoc(input.IssuedSdJwt);
        
        Assert.That(doc.UnsecuredPayload, Is.EqualTo(JObject.Parse(input.UnsecuredPayload)));
        Assert.That(doc.SecuredPayload, Is.EqualTo(JObject.Parse(input.SecuredPayload)));
        Assert.That(doc.Disclosures.Count, Is.EqualTo(input.NumberOfDisclosures));
    }
}