# SD-JWT for .NET (Experimental)

This is an experimental implementation of the sd-jwt specification. The purpose of this was to understand the serialisation and deserialisation of the combined issuance and presentation formats.

# Requirements

The intention was to use the minimum amount of dependencies, but I also tried out differnt jwt libraries for decoding and encoding therefore the project currently has more dependencies than necesarry

## Askar

To test the signing of sd-jwt with aries-askar you have to build the askar library for your platform and import the askar wrapper from [Github](https://github.com/esatus/aries-askar).

Update the path to the `aries-askar-dotnet.csproj` file in `src/SD-JWT-Askar/SD-JWT-Askar.csproj` and `SD-JWT.sln`