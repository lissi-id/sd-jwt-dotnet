using SD_JWT.Models;

namespace SD_JWT_Tests;

public class SdJwtDocTests
{
    private const string sdJwtIssued =
        "eyJhbGciOiAiRVMyNTYifQ.eyJpc3MiOiAiaHR0cHM6Ly9leGFtcGxlLmNvbS9pc3N1ZXIiLCAiaWF0IjogMTUxNjIzOTAyMiwgInR5cGUiOiAiTmV4dENsb3VkTG9naW4iLCAiY29uZmlybWF0aW9uTWV0aG9kcyI6IFt7InR5cGUiOiAiUmF3S2V5QmluZGluZyIsICJqd2siOiB7ImNydiI6ICJQLTI1NiIsICJrdHkiOiAiRUMiLCAieCI6ICJhY2JJUWl1TXMzaThfdXN6RWpKMnRwVHRSTTRFVTN5ejkxUEg2Q2RIMlYwIiwgInkiOiAiX0tjeUxqOXZXTXB0bm1LdG00NkdxRHo4d2Y3NEk1TEtncmwyR3pIM25TRSJ9fV0sICJjcmVkZW50aWFsU3ViamVjdCI6IHsiX3NkIjogWyI4VG1kbkRRekVFTDIyM3hESm43SjJiZ0UyMTd1VTQ5aGFLV1B0bXM0VW1ZIiwgIm5kbmh0WlNkdVJ1S2xJNW1nd3JzcV95TlNHakgtRF9pSzFORm9LMzgyc2MiLCAid2ZBb0x3eExlWTdodHJrSGpJUjF5dGxJSFFLMzh1LVNYd0JvNXlNRVQtUSJdfSwgImV4cCI6IDE1MTYyNDcwMjIsICJfc2RfYWxnIjogInNoYS0yNTYiLCAiY25mIjogeyJqd2siOiB7Imt0eSI6ICJFQyIsICJjcnYiOiAiUC0yNTYiLCAieCI6ICJUQ0FFUjE5WnZ1M09IRjRqNFc0dmZTVm9ISVAxSUxpbERsczd2Q2VHZW1jIiwgInkiOiAiWnhqaVdXYlpNUUdIVldLVlE0aGJTSWlyc1ZmdWVjQ0U2dDRqVDlGMkhaUSJ9fX0.0WL_y5wp6G1Zcs2W_UzD9nrS98Z8y8USj_JMyaJCHBevQSVirFSVA7Lhjx_MDcymCTxgXGd5WkzOLsVHgzjDeA~WyJ2MzFXTXB4bU9PY3g3d0xqQ2dzOWN3IiwgImdpdmVuX25hbWUiLCAiRXJpa2EiXQ~WyJySTVmM3M5S2VEZHExMU80cHhfbkhBIiwgImZhbWlseV9uYW1lIiwgIk11c3Rlcm1hbm4iXQ~WyJBdlgtWUV3N3FQX3o0YkkwUmVnUzZnIiwgImVtYWlsIiwgInRlc3RAZXhhbXBsZS5jb20iXQ";

    private const string sdJwtPresentedWithoutConfirmation =
        "eyJhbGciOiAiRVMyNTYifQ.eyJpc3MiOiAiaHR0cHM6Ly9leGFtcGxlLmNvbS9pc3N1ZXIiLCAiaWF0IjogMTUxNjIzOTAyMiwgInR5cGUiOiAiTmV4dENsb3VkTG9naW4iLCAiY29uZmlybWF0aW9uTWV0aG9kcyI6IFt7InR5cGUiOiAiUmF3S2V5QmluZGluZyIsICJqd2siOiB7ImNydiI6ICJQLTI1NiIsICJrdHkiOiAiRUMiLCAieCI6ICJhY2JJUWl1TXMzaThfdXN6RWpKMnRwVHRSTTRFVTN5ejkxUEg2Q2RIMlYwIiwgInkiOiAiX0tjeUxqOXZXTXB0bm1LdG00NkdxRHo4d2Y3NEk1TEtncmwyR3pIM25TRSJ9fV0sICJjcmVkZW50aWFsU3ViamVjdCI6IHsiX3NkIjogWyI4VG1kbkRRekVFTDIyM3hESm43SjJiZ0UyMTd1VTQ5aGFLV1B0bXM0VW1ZIiwgIm5kbmh0WlNkdVJ1S2xJNW1nd3JzcV95TlNHakgtRF9pSzFORm9LMzgyc2MiLCAid2ZBb0x3eExlWTdodHJrSGpJUjF5dGxJSFFLMzh1LVNYd0JvNXlNRVQtUSJdfSwgImV4cCI6IDE1MTYyNDcwMjIsICJfc2RfYWxnIjogInNoYS0yNTYiLCAiY25mIjogeyJqd2siOiB7Imt0eSI6ICJFQyIsICJjcnYiOiAiUC0yNTYiLCAieCI6ICJUQ0FFUjE5WnZ1M09IRjRqNFc0dmZTVm9ISVAxSUxpbERsczd2Q2VHZW1jIiwgInkiOiAiWnhqaVdXYlpNUUdIVldLVlE0aGJTSWlyc1ZmdWVjQ0U2dDRqVDlGMkhaUSJ9fX0.0WL_y5wp6G1Zcs2W_UzD9nrS98Z8y8USj_JMyaJCHBevQSVirFSVA7Lhjx_MDcymCTxgXGd5WkzOLsVHgzjDeA~WyJ2MzFXTXB4bU9PY3g3d0xqQ2dzOWN3IiwgImdpdmVuX25hbWUiLCAiRXJpa2EiXQ~WyJySTVmM3M5S2VEZHExMU80cHhfbkhBIiwgImZhbWlseV9uYW1lIiwgIk11c3Rlcm1hbm4iXQ~";
    
    [Test]
    public void CanParseSdJwt()
    {
        var doc = new SdJwtDoc(sdJwtIssued);
        
        Assert.That(doc.Disclosures.Count, Is.EqualTo(3));
    }
}