using SD_JWT.Models;

namespace SD_JWT_Tests;

public class DisclosureTests
{
    private const string SerialisedDisclosure = "WyJfMjZiYzRMVC1hYzZxMktJNmNCVzVlcyIsImZhbWlseV9uYW1lIiwiTVx1MDBGNmJpdXMiXQ";
    private readonly Disclosure DeserialisedDisclosure = 
        new("family_name", "Möbius") { Salt = "_26bc4LT-ac6q2KI6cBW5es" };

    [SetUp]
    public void Setup()
    {
    }

    [Test]
    public void CanSerializeDisclosure()
    {
        Assert.That(SerialisedDisclosure, Is.EqualTo(DeserialisedDisclosure.Serialize()));
    }

    [Test]
    public void CanDeserializeDisclosure()
    {
        Assert.That(DeserialisedDisclosure.Salt,  Is.EqualTo(Disclosure.Deserialize(SerialisedDisclosure).Salt));
        Assert.That(DeserialisedDisclosure.Name,  Is.EqualTo(Disclosure.Deserialize(SerialisedDisclosure).Name));
        Assert.That(DeserialisedDisclosure.Value,  Is.EqualTo(Disclosure.Deserialize(SerialisedDisclosure).Value.ToString()));
    }

    [Test]
    public void CanComputeHash()
    {
        const string expectedHash = "X-iQ9cBjlRvwtSc2v6NNJiZkvm98vDKXJhS-5JHUt6k";

        string actualHash = DeserialisedDisclosure.GetDigest();
        
        Assert.That(expectedHash, Is.EqualTo(actualHash));
    }
}