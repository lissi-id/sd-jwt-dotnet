using SD_JWT;
using SD_JWT.Abstractions;
using SD_JWT.Models;

namespace SD_JWT_Tests;

public class HolderTests
{
    private const string sdJwtIssued =
        "eyJhbGciOiAiRVMyNTYifQ.eyJpc3MiOiAiaHR0cHM6Ly9leGFtcGxlLmNvbS9pc3N1ZXIiLCAiaWF0IjogMTUxNjIzOTAyMiwgInR5cGUiOiAiTmV4dENsb3VkTG9naW4iLCAiY29uZmlybWF0aW9uTWV0aG9kcyI6IFt7InR5cGUiOiAiUmF3S2V5QmluZGluZyIsICJqd2siOiB7ImNydiI6ICJQLTI1NiIsICJrdHkiOiAiRUMiLCAieCI6ICJhY2JJUWl1TXMzaThfdXN6RWpKMnRwVHRSTTRFVTN5ejkxUEg2Q2RIMlYwIiwgInkiOiAiX0tjeUxqOXZXTXB0bm1LdG00NkdxRHo4d2Y3NEk1TEtncmwyR3pIM25TRSJ9fV0sICJjcmVkZW50aWFsU3ViamVjdCI6IHsiX3NkIjogWyI4VG1kbkRRekVFTDIyM3hESm43SjJiZ0UyMTd1VTQ5aGFLV1B0bXM0VW1ZIiwgIm5kbmh0WlNkdVJ1S2xJNW1nd3JzcV95TlNHakgtRF9pSzFORm9LMzgyc2MiLCAid2ZBb0x3eExlWTdodHJrSGpJUjF5dGxJSFFLMzh1LVNYd0JvNXlNRVQtUSJdfSwgImV4cCI6IDE1MTYyNDcwMjIsICJfc2RfYWxnIjogInNoYS0yNTYiLCAiY25mIjogeyJqd2siOiB7Imt0eSI6ICJFQyIsICJjcnYiOiAiUC0yNTYiLCAieCI6ICJUQ0FFUjE5WnZ1M09IRjRqNFc0dmZTVm9ISVAxSUxpbERsczd2Q2VHZW1jIiwgInkiOiAiWnhqaVdXYlpNUUdIVldLVlE0aGJTSWlyc1ZmdWVjQ0U2dDRqVDlGMkhaUSJ9fX0.0WL_y5wp6G1Zcs2W_UzD9nrS98Z8y8USj_JMyaJCHBevQSVirFSVA7Lhjx_MDcymCTxgXGd5WkzOLsVHgzjDeA~WyJ2MzFXTXB4bU9PY3g3d0xqQ2dzOWN3IiwgImdpdmVuX25hbWUiLCAiRXJpa2EiXQ~WyJySTVmM3M5S2VEZHExMU80cHhfbkhBIiwgImZhbWlseV9uYW1lIiwgIk11c3Rlcm1hbm4iXQ~WyJBdlgtWUV3N3FQX3o0YkkwUmVnUzZnIiwgImVtYWlsIiwgInRlc3RAZXhhbXBsZS5jb20iXQ";

    private const string sdJwtPresentedWithoutConfirmation =
        "eyJhbGciOiAiRVMyNTYifQ.eyJpc3MiOiAiaHR0cHM6Ly9leGFtcGxlLmNvbS9pc3N1ZXIiLCAiaWF0IjogMTUxNjIzOTAyMiwgInR5cGUiOiAiTmV4dENsb3VkTG9naW4iLCAiY29uZmlybWF0aW9uTWV0aG9kcyI6IFt7InR5cGUiOiAiUmF3S2V5QmluZGluZyIsICJqd2siOiB7ImNydiI6ICJQLTI1NiIsICJrdHkiOiAiRUMiLCAieCI6ICJhY2JJUWl1TXMzaThfdXN6RWpKMnRwVHRSTTRFVTN5ejkxUEg2Q2RIMlYwIiwgInkiOiAiX0tjeUxqOXZXTXB0bm1LdG00NkdxRHo4d2Y3NEk1TEtncmwyR3pIM25TRSJ9fV0sICJjcmVkZW50aWFsU3ViamVjdCI6IHsiX3NkIjogWyI4VG1kbkRRekVFTDIyM3hESm43SjJiZ0UyMTd1VTQ5aGFLV1B0bXM0VW1ZIiwgIm5kbmh0WlNkdVJ1S2xJNW1nd3JzcV95TlNHakgtRF9pSzFORm9LMzgyc2MiLCAid2ZBb0x3eExlWTdodHJrSGpJUjF5dGxJSFFLMzh1LVNYd0JvNXlNRVQtUSJdfSwgImV4cCI6IDE1MTYyNDcwMjIsICJfc2RfYWxnIjogInNoYS0yNTYiLCAiY25mIjogeyJqd2siOiB7Imt0eSI6ICJFQyIsICJjcnYiOiAiUC0yNTYiLCAieCI6ICJUQ0FFUjE5WnZ1M09IRjRqNFc0dmZTVm9ISVAxSUxpbERsczd2Q2VHZW1jIiwgInkiOiAiWnhqaVdXYlpNUUdIVldLVlE0aGJTSWlyc1ZmdWVjQ0U2dDRqVDlGMkhaUSJ9fX0.0WL_y5wp6G1Zcs2W_UzD9nrS98Z8y8USj_JMyaJCHBevQSVirFSVA7Lhjx_MDcymCTxgXGd5WkzOLsVHgzjDeA~WyJBdlgtWUV3N3FQX3o0YkkwUmVnUzZnIiwgImVtYWlsIiwgInRlc3RAZXhhbXBsZS5jb20iXQ";
    
    private const string validFlatJwt =
        "eyJraWQiOiJ6emVVbkwzNVZPOVZkel9pUk5HUml3ODlpOENOdXdsNldZZ1h6aWdGdlhJIiwiYWxnIjoiRVMyNTYiLCJ0eXAiOiJ2YytzZC1qd3QifQ.eyJfc2QiOlsiZk9CVVNRdm80NnlRTy13UndYQmNHcXZuYktJdWVJU0VMOTYxX1NqZDRkbyJdLCJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlLmNvbSIsImlhdCI6MTY4MzAwMDAwMCwiZXhwIjoyMTQ3NDgzNjQ2LCJ2Y3QiOiJGbGF0IEp3dCIsInN1YiI6IjZjNWMwYTQ5LWI1ODktNDMxZC1iYWU3LTIxOTEyMmE5ZWMyYyIsIl9zZF9hbGciOiJzaGEtMjU2In0.Kaz4JZg3lav5GWvFtg_j-w7uDosUoMHjDt-iAldBJ_uK3HHAmDU4pYtqu143yKvk7cKsvP869Vs6AipO4LLQUw~WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgImFkZHJlc3MiLCB7InN0cmVldF9hZGRyZXNzIjogIlNjaHVsc3RyLiAxMiIsICJsb2NhbGl0eSI6ICJTY2h1bHBmb3J0YSIsICJyZWdpb24iOiAiU2FjaHNlbi1BbmhhbHQiLCAiY291bnRyeSI6ICJERSJ9XQ~";

    private const string validStructuredJwt =
        "eyJraWQiOiJ6emVVbkwzNVZPOVZkel9pUk5HUml3ODlpOENOdXdsNldZZ1h6aWdGdlhJIiwiYWxnIjoiRVMyNTYiLCJ0eXAiOiJ2YytzZC1qd3QifQ.eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlLmNvbSIsImlhdCI6MTY4MzAwMDAwMCwiZXhwIjoyMTQ3NDgzNjQ2LCJzdWIiOiI2YzVjMGE0OS1iNTg5LTQzMWQtYmFlNy0yMTkxMjJhOWVjMmMiLCJ2Y3QiOiJTdHJ1Y3R1cmVkIEp3dCIsImFkZHJlc3MiOnsiX3NkIjpbIjZ2aDlicS16UzRHS01fN0dwZ2dWYll6enU2b09HWHJtTlZHUEhQNzVVZDAiLCI5Z2pWdVh0ZEZST0NnUnJ0TmNHVVhtRjY1cmRlemlfNkVyX2o3NmttWXlNIiwiS1VSRFBoNFpDMTktM3Rpei1EZjM5VjhlaWR5MW9WM2EzSDFEYTJOMGc4OCIsIldOOXI5ZENCSjhIVENzUzJqS0FTeFRqRXlXNW01eDY1X1pfMnJvMmpmWE0iXX0sIl9zZF9hbGciOiJzaGEtMjU2In0.PlxgvNfyeEi_lyDSz9p9Tfbzad967zdskupI3qgm92_SEatpiBYsi1QKMkeeD67PfuERgb4RVosIKgPshG0C7g~WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgInN0cmVldF9hZGRyZXNzIiwgIlNjaHVsc3RyLiAxMiJd~WyJlbHVWNU9nM2dTTklJOEVZbnN4QV9BIiwgImxvY2FsaXR5IiwgIlNjaHVscGZvcnRhIl0~WyI2SWo3dE0tYTVpVlBHYm9TNXRtdlZBIiwgInJlZ2lvbiIsICJTYWNoc2VuLUFuaGFsdCJd~WyJlSThaV205UW5LUHBOUGVOZW5IZGhRIiwgImNvdW50cnkiLCAiREUiXQ~";
    
    private const string validRecursiveJwt =
        "eyJraWQiOiJ6emVVbkwzNVZPOVZkel9pUk5HUml3ODlpOENOdXdsNldZZ1h6aWdGdlhJIiwiYWxnIjoiRVMyNTYiLCJ0eXAiOiJ2YytzZC1qd3QifQ.eyJfc2QiOlsiSHZyS1g2ZlBWMHY5S195Q1ZGQmlMRkhzTWF4Y0RfMTE0RW02VlQ4eDFsZyJdLCJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlLmNvbSIsImlhdCI6MTY4MzAwMDAwMCwiZXhwIjoyMTQ3NDgzNjQ3LCJ2Y3QiOiJSZWN1cnNpdmUgSnd0Iiwic3ViIjoiNmM1YzBhNDktYjU4OS00MzFkLWJhZTctMjE5MTIyYTllYzJjIiwiX3NkX2FsZyI6InNoYS0yNTYifQ.85fzoCN2DZ9KjbVyQPA3quv-GnrnxEl-FG3e5CJx5w9a-W4BhfILVoyQPmrUfNKjNolrlAuTIfjuAPkqSUn4MA~WyJ2MzFXTXB4bU9PY3g3d0xqQ2dzOWN3IiwgImdpdmVuX25hbWUiLCAiRXJpa2EiXQ=~WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgInN0cmVldF9hZGRyZXNzIiwgIlNjaHVsc3RyLiAxMiJd~WyJlbHVWNU9nM2dTTklJOEVZbnN4QV9BIiwgImxvY2FsaXR5IiwgIlNjaHVscGZvcnRhIl0~WyI2SWo3dE0tYTVpVlBHYm9TNXRtdlZBIiwgInJlZ2lvbiIsICJTYWNoc2VuLUFuaGFsdCJd~WyJlSThaV205UW5LUHBOUGVOZW5IZGhRIiwgImNvdW50cnkiLCAiREUiXQ~WyJRZ19PNjR6cUF4ZTQxMmExMDhpcm9BIiwgImFkZHJlc3MiLCB7Il9zZCI6IFsiNnZoOWJxLXpTNEdLTV83R3BnZ1ZiWXp6dTZvT0dYcm1OVkdQSFA3NVVkMCIsICI5Z2pWdVh0ZEZST0NnUnJ0TmNHVVhtRjY1cmRlemlfNkVyX2o3NmttWXlNIiwgIktVUkRQaDRaQzE5LTN0aXotRGYzOVY4ZWlkeTFvVjNhM0gxRGEyTjBnODgiLCAiV045cjlkQ0JKOEhUQ3NTMmpLQVN4VGpFeVc1bTV4NjVfWl8ycm8yamZYTSJdfV0~";

    private const string validComplexStructuredJwt =
        "eyJraWQiOiJ6emVVbkwzNVZPOVZkel9pUk5HUml3ODlpOENOdXdsNldZZ1h6aWdGdlhJIiwiYWxnIjoiRVMyNTYiLCJ0eXAiOiJ2YytzZC1qd3QifQ.eyJfc2QiOlsiLWFTem5JZDltV004b2N1UW9sQ2xsc3hWZ2dxMS12SFc0T3RuaFV0Vm1XdyIsIklLYnJZTm4zdkE3V0VGcnlzdmJkQkpqRERVX0V2UUlyMFcxOHZUUnBVU2ciLCJvdGt4dVQxNG5CaXd6TkozTVBhT2l0T2w5cFZuWE9hRUhhbF94a3lOZktJIl0sImlzcyI6Imh0dHBzOi8vaXNzdWVyLmV4YW1wbGUuY29tIiwiaWF0IjoxNjgzMDAwMDAwLCJleHAiOjIxNDc0ODM2NDcsInZjdCI6IkNvbXBsZXggSnd0IiwidmVyaWZpZWRfY2xhaW1zIjp7InZlcmlmaWNhdGlvbiI6eyJfc2QiOlsiN2g0VUU5cVNjdkRLb2RYVkN1b0tmS0JKcFZCZlhNRl9UbUFHVmFaZTNTYyIsInZUd2UzcmFISUZZZ0ZBM3hhVUQyYU14Rno1b0RvOGlCdTA1cUtsT2c5THciXSwidHJ1c3RfZnJhbWV3b3JrIjoiZGVfYW1sIiwiZXZpZGVuY2UiOlt7Ii4uLiI6InRZSjBURHVjeVpaQ1JNYlJPRzRxUk81dmtQU0ZSeEZoVUVMYzE4Q1NsM2sifV19LCJjbGFpbXMiOnsiX3NkIjpbIlJpT2lDbjZfdzVaSGFhZGtRTXJjUUpmMEp0ZTVSd3VyUnM1NDIzMURUbG8iLCJTXzQ5OGJicEt6QjZFYW5mdHNzMHhjN2NPYW9uZVJyM3BLcjdOZFJtc01vIiwiV05BLVVOSzdGX3poc0FiOXN5V082SUlRMXVIbFRtT1U4cjhDdkowY0lNayIsIld4aF9zVjNpUkg5YmdyVEJKaS1hWUhOQ0x0LXZqaFgxc2QtaWdPZl85bGsiLCJfTy13SmlIM2VuU0I0Uk9IbnRUb1FUOEptTHR6LW1oTzJmMWM4OVhvZXJRIiwiaHZEWGh3bUdjSlFzQkNBMk90anVMQWN3QU1wRHNhVTBua292Y0tPcVdORSJdfX0sIl9zZF9hbGciOiJzaGEtMjU2In0.pb9BH-wplbbZ-gQfewgfpfZh_DqQCrhX3qboQo2nMKa_WxVsv9GUAJtVB34oLtRSjz0Hbsm-KIlAnSSG5vXXyg~WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgInRpbWUiLCAiMjAxMi0wNC0yM1QxODoyNVoiXQ~WyJlbHVWNU9nM2dTTklJOEVZbnN4QV9BIiwgInZlcmlmaWNhdGlvbl9wcm9jZXNzIiwgImYyNGM2Zi02ZDNmLTRlYzUtOTczZS1iMGQ4NTA2ZjNiYzciXQ~WyI2SWo3dE0tYTVpVlBHYm9TNXRtdlZBIiwgInR5cGUiLCAiZG9jdW1lbnQiXQ~WyJlSThaV205UW5LUHBOUGVOZW5IZGhRIiwgIm1ldGhvZCIsICJwaXBwIl0~WyJRZ19PNjR6cUF4ZTQxMmExMDhpcm9BIiwgInRpbWUiLCAiMjAxMi0wNC0yMlQxMTozMFoiXQ~WyJBSngtMDk1VlBycFR0TjRRTU9xUk9BIiwgImRvY3VtZW50IiwgeyJ0eXBlIjogImlkY2FyZCIsICJpc3N1ZXIiOiB7Im5hbWUiOiAiU3RhZHQgQXVnc2J1cmciLCAiY291bnRyeSI6ICJERSJ9LCAibnVtYmVyIjogIjUzNTU0NTU0IiwgImRhdGVfb2ZfaXNzdWFuY2UiOiAiMjAxMC0wMy0yMyIsICJkYXRlX29mX2V4cGlyeSI6ICIyMDIwLTAzLTIyIn1d~WyJQYzMzSk0yTGNoY1VfbEhnZ3ZfdWZRIiwgeyJfc2QiOiBbIjl3cGpWUFd1RDdQSzBuc1FETDhCMDZsbWRnVjNMVnliaEh5ZFFwVE55TEkiLCAiRzVFbmhPQU9vVTlYXzZRTU52ekZYanBFQV9SYy1BRXRtMWJHX3djYUtJayIsICJJaHdGcldVQjYzUmNacTl5dmdaMFhQYzdHb3doM08ya3FYZUJJc3dnMUI0IiwgIldweFE0SFNvRXRjVG1DQ0tPZURzbEJfZW11Y1lMejJvTzhvSE5yMWJFVlEiXX1d~WyJHMDJOU3JRZmpGWFE3SW8wOXN5YWpBIiwgImdpdmVuX25hbWUiLCAiTWF4Il0~WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgImZhbWlseV9uYW1lIiwgIk1cdTAwZmNsbGVyIl0~WyJuUHVvUW5rUkZxM0JJZUFtN0FuWEZBIiwgIm5hdGlvbmFsaXRpZXMiLCBbIkRFIl1d~WyI1YlBzMUlxdVpOYTBoa2FGenp6Wk53IiwgImJpcnRoZGF0ZSIsICIxOTU2LTAxLTI4Il0~WyI1YTJXMF9OcmxFWnpmcW1rXzdQcS13IiwgInBsYWNlX29mX2JpcnRoIiwgeyJjb3VudHJ5IjogIklTIiwgImxvY2FsaXR5IjogIlx1MDBkZXlra3ZhYlx1MDBlNmphcmtsYXVzdHVyIn1d~WyJ5MXNWVTV3ZGZKYWhWZGd3UGdTN1JRIiwgImFkZHJlc3MiLCB7ImxvY2FsaXR5IjogIk1heHN0YWR0IiwgInBvc3RhbF9jb2RlIjogIjEyMzQ0IiwgImNvdW50cnkiOiAiREUiLCAic3RyZWV0X2FkZHJlc3MiOiAiV2VpZGVuc3RyYVx1MDBkZmUgMjIifV0~WyJIYlE0WDhzclZXM1FEeG5JSmRxeU9BIiwgImJpcnRoX21pZGRsZV9uYW1lIiwgIlRpbW90aGV1cyJd~WyJDOUdTb3VqdmlKcXVFZ1lmb2pDYjFBIiwgInNhbHV0YXRpb24iLCAiRHIuIl0~WyJreDVrRjE3Vi14MEptd1V4OXZndnR3IiwgIm1zaXNkbiIsICI0OTEyMzQ1Njc4OSJd~";
    
    private const string invalidFlatJwtWithKbJwt =
        "eyJraWQiOiJ6emVVbkwzNVZPOVZkel9pUk5HUml3ODlpOENOdXdsNldZZ1h6aWdGdlhJIiwiYWxnIjoiRVMyNTYifQ.eyJfc2QiOlsiZk9CVVNRdm80NnlRTy13UndYQmNHcXZuYktJdWVJU0VMOTYxX1NqZDRkbyJdLCJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlLmNvbSIsImlhdCI6MTY4MzAwMDAwMCwiZXhwIjo5ODgzMDAwMDAwLCJ2Y3QiOiJGbGF0IEp3dCIsInN1YiI6IjZjNWMwYTQ5LWI1ODktNDMxZC1iYWU3LTIxOTEyMmE5ZWMyYyIsIl9zZF9hbGciOiJzaGEtMjU2In0.vYrLGzIdXm1D9bjOf-ZFXPR7nnJALVMWK9eXg9N9Q-6cQY-Haqudn16UuK-LNWyOPalXWSJ86A4faPG9KpTFpQ~WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgImFkZHJlc3MiLCB7InN0cmVldF9hZGRyZXNzIjogIlNjaHVsc3RyLiAxMiIsICJsb2NhbGl0eSI6ICJTY2h1bHBmb3J0YSIsICJyZWdpb24iOiAiU2FjaHNlbi1BbmhhbHQiLCAiY291bnRyeSI6ICJERSJ9XQ~eyJraWQiOiJ6emVVbkwzNVZPOVZkel9pUk5HUml3ODlpOENOdXdsNldZZ1h6aWdGdlhJIiwiYWxnIjoiRVMyNTYifQ.eyJfc2QiOlsiZk9CVVNRdm80NnlRTy13UndYQmNHcXZuYktJdWVJU0VMOTYxX1NqZDRkbyJdLCJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlLmNvbSIsImlhdCI6MTY4MzAwMDAwMCwiZXhwIjo5ODgzMDAwMDAwLCJ2Y3QiOiJGbGF0IEp3dCIsInN1YiI6IjZjNWMwYTQ5LWI1ODktNDMxZC1iYWU3LTIxOTEyMmE5ZWMyYyIsIl9zZF9hbGciOiJzaGEtMjU2In0.vYrLGzIdXm1D9bjOf-ZFXPR7nnJALVMWK9eXg9N9Q-6cQY-Haqudn16UuK-LNWyOPalXWSJ86A4faPG9KpTFpQ";

    private const string invalidExpiredFlatJwt =
        "eyJraWQiOiJ6emVVbkwzNVZPOVZkel9pUk5HUml3ODlpOENOdXdsNldZZ1h6aWdGdlhJIiwiYWxnIjoiRVMyNTYifQ.eyJfc2QiOlsiZk9CVVNRdm80NnlRTy13UndYQmNHcXZuYktJdWVJU0VMOTYxX1NqZDRkbyJdLCJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlLmNvbSIsImlhdCI6MTY4MzAwMDAwMCwiZXhwIjoxMTgzMDAwMDAwLCJ2Y3QiOiJFeHBpcmVkIEZsYXQgSnd0Iiwic3ViIjoiNmM1YzBhNDktYjU4OS00MzFkLWJhZTctMjE5MTIyYTllYzJjIiwiX3NkX2FsZyI6InNoYS0yNTYifQ.uiK3RIQRPzHqriM9eihwYK_aVPTM03efBpzBtv806JLFjoTr34DgmpTy9BpbERLztkF9gdfO6l7MhEd5T_gL4A~WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgImFkZHJlc3MiLCB7InN0cmVldF9hZGRyZXNzIjogIlNjaHVsc3RyLiAxMiIsICJsb2NhbGl0eSI6ICJTY2h1bHBmb3J0YSIsICJyZWdpb24iOiAiU2FjaHNlbi1BbmhhbHQiLCAiY291bnRyeSI6ICJERSJ9XQ~";

    private const string validFlatJwtWithInvalidSignature =
        "eyJraWQiOiJ6emVVbkwzNVZPOVZkel9pUk5HUml3ODlpOENOdXdsNldZZ1h6aWdGdlhJIiwiYWxnIjoiRVMyNTYiLCJ0eXAiOiJ2YytzZC1qd3QifQ.eyJfc2QiOlsiZk9CVVNRdm80NnlRTy13UndYQmNHcXZuYktJdWVJU0VMOTYxX1NqZDRkbyJdLCJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlLmNvbSIsImlhdCI6MTY4MzAwMDAwMCwiZXhwIjoyMTQ3NDgzNjQ2LCJ2Y3QiOiJGbGF0IEp3dCIsInN1YiI6IjZjNWMwYTQ5LWI1ODktNDMxZC1iYWU3LTIxOTEyMmE5ZWMyYyIsIl9zZF9hbGciOiJzaGEtMjU2In0.Kaz4JZg3lav5GWvFtg_j-w7uDosUoMHjDt-iAldBJ_uK3HHAmDU4pYtqu143yKvk7cKsvP869Vs6AipO4LLQU~WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgImFkZHJlc3MiLCB7InN0cmVldF9hZGRyZXNzIjogIlNjaHVsc3RyLiAxMiIsICJsb2NhbGl0eSI6ICJTY2h1bHBmb3J0YSIsICJyZWdpb24iOiAiU2FjaHNlbi1BbmhhbHQiLCAiY291bnRyeSI6ICJERSJ9XQ~";
    
    private const string invalidFlatJwtWithRepeatingDigests =
        "eyJraWQiOiJ6emVVbkwzNVZPOVZkel9pUk5HUml3ODlpOENOdXdsNldZZ1h6aWdGdlhJIiwiYWxnIjoiRVMyNTYiLCJ0eXAiOiJ2YytzZC1qd3QifQ.eyJfc2QiOlsiLWFTem5JZDltV004b2N1UW9sQ2xsc3hWZ2dxMS12SFc0T3RuaFV0Vm1XdyIsIlNfNDk4YmJwS3pCNkVhbmZ0c3MweGM3Y09hb25lUnIzcEtyN05kUm1zTW8iLCJvdGt4dVQxNG5CaXd6TkozTVBhT2l0T2w5cFZuWE9hRUhhbF94a3lOZktJIl0sImlzcyI6Imh0dHBzOi8vaXNzdWVyLmV4YW1wbGUuY29tIiwiaWF0IjoxNjgzMDAwMDAwLCJleHAiOjIxNDc0ODM2NDcsInZjdCI6IkNvbXBsZXggSnd0IiwidmVyaWZpZWRfY2xhaW1zIjp7InZlcmlmaWNhdGlvbiI6eyJfc2QiOlsiN2g0VUU5cVNjdkRLb2RYVkN1b0tmS0JKcFZCZlhNRl9UbUFHVmFaZTNTYyIsInZUd2UzcmFISUZZZ0ZBM3hhVUQyYU14Rno1b0RvOGlCdTA1cUtsT2c5THciXSwidHJ1c3RfZnJhbWV3b3JrIjoiZGVfYW1sIiwiZXZpZGVuY2UiOlt7Ii4uLiI6InRZSjBURHVjeVpaQ1JNYlJPRzRxUk81dmtQU0ZSeEZoVUVMYzE4Q1NsM2sifV19LCJjbGFpbXMiOnsiX3NkIjpbIlJpT2lDbjZfdzVaSGFhZGtRTXJjUUpmMEp0ZTVSd3VyUnM1NDIzMURUbG8iLCJTXzQ5OGJicEt6QjZFYW5mdHNzMHhjN2NPYW9uZVJyM3BLcjdOZFJtc01vIiwiV05BLVVOSzdGX3poc0FiOXN5V082SUlRMXVIbFRtT1U4cjhDdkowY0lNayIsIld4aF9zVjNpUkg5YmdyVEJKaS1hWUhOQ0x0LXZqaFgxc2QtaWdPZl85bGsiLCJfTy13SmlIM2VuU0I0Uk9IbnRUb1FUOEptTHR6LW1oTzJmMWM4OVhvZXJRIiwiaHZEWGh3bUdjSlFzQkNBMk90anVMQWN3QU1wRHNhVTBua292Y0tPcVdORSJdfX0sIl9zZF9hbGciOiJzaGEtMjU2In0.MJUOYtL0bzxodIyssjg3JKtV4JCKaxSMOYRuilPoT65oNzfeUOLJP_Zy94nfKlUQj8ZZDNEAL_j6Vmlm60b0tw~WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgInRpbWUiLCAiMjAxMi0wNC0yM1QxODoyNVoiXQ~WyJlbHVWNU9nM2dTTklJOEVZbnN4QV9BIiwgInZlcmlmaWNhdGlvbl9wcm9jZXNzIiwgImYyNGM2Zi02ZDNmLTRlYzUtOTczZS1iMGQ4NTA2ZjNiYzciXQ~WyI2SWo3dE0tYTVpVlBHYm9TNXRtdlZBIiwgInR5cGUiLCAiZG9jdW1lbnQiXQ~WyJlSThaV205UW5LUHBOUGVOZW5IZGhRIiwgIm1ldGhvZCIsICJwaXBwIl0~WyJRZ19PNjR6cUF4ZTQxMmExMDhpcm9BIiwgInRpbWUiLCAiMjAxMi0wNC0yMlQxMTozMFoiXQ~WyJBSngtMDk1VlBycFR0TjRRTU9xUk9BIiwgImRvY3VtZW50IiwgeyJ0eXBlIjogImlkY2FyZCIsICJpc3N1ZXIiOiB7Im5hbWUiOiAiU3RhZHQgQXVnc2J1cmciLCAiY291bnRyeSI6ICJERSJ9LCAibnVtYmVyIjogIjUzNTU0NTU0IiwgImRhdGVfb2ZfaXNzdWFuY2UiOiAiMjAxMC0wMy0yMyIsICJkYXRlX29mX2V4cGlyeSI6ICIyMDIwLTAzLTIyIn1d~WyJQYzMzSk0yTGNoY1VfbEhnZ3ZfdWZRIiwgeyJfc2QiOiBbIjl3cGpWUFd1RDdQSzBuc1FETDhCMDZsbWRnVjNMVnliaEh5ZFFwVE55TEkiLCAiRzVFbmhPQU9vVTlYXzZRTU52ekZYanBFQV9SYy1BRXRtMWJHX3djYUtJayIsICJJaHdGcldVQjYzUmNacTl5dmdaMFhQYzdHb3doM08ya3FYZUJJc3dnMUI0IiwgIldweFE0SFNvRXRjVG1DQ0tPZURzbEJfZW11Y1lMejJvTzhvSE5yMWJFVlEiXX1d~WyJHMDJOU3JRZmpGWFE3SW8wOXN5YWpBIiwgImdpdmVuX25hbWUiLCAiTWF4Il0~WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgImZhbWlseV9uYW1lIiwgIk1cdTAwZmNsbGVyIl0~WyJuUHVvUW5rUkZxM0JJZUFtN0FuWEZBIiwgIm5hdGlvbmFsaXRpZXMiLCBbIkRFIl1d~WyI1YlBzMUlxdVpOYTBoa2FGenp6Wk53IiwgImJpcnRoZGF0ZSIsICIxOTU2LTAxLTI4Il0~WyI1YTJXMF9OcmxFWnpmcW1rXzdQcS13IiwgInBsYWNlX29mX2JpcnRoIiwgeyJjb3VudHJ5IjogIklTIiwgImxvY2FsaXR5IjogIlx1MDBkZXlra3ZhYlx1MDBlNmphcmtsYXVzdHVyIn1d~WyJ5MXNWVTV3ZGZKYWhWZGd3UGdTN1JRIiwgImFkZHJlc3MiLCB7ImxvY2FsaXR5IjogIk1heHN0YWR0IiwgInBvc3RhbF9jb2RlIjogIjEyMzQ0IiwgImNvdW50cnkiOiAiREUiLCAic3RyZWV0X2FkZHJlc3MiOiAiV2VpZGVuc3RyYVx1MDBkZmUgMjIifV0~WyJIYlE0WDhzclZXM1FEeG5JSmRxeU9BIiwgImJpcnRoX21pZGRsZV9uYW1lIiwgIlRpbW90aGV1cyJd~WyJDOUdTb3VqdmlKcXVFZ1lmb2pDYjFBIiwgInNhbHV0YXRpb24iLCAiRHIuIl0~WyJreDVrRjE3Vi14MEptd1V4OXZndnR3IiwgIm1zaXNkbiIsICI0OTEyMzQ1Njc4OSJd~";

    private const string invalidFlatJwtWithInvalidIssuer =
        "eyJraWQiOiJ6emVVbkwzNVZPOVZkel9pUk5HUml3ODlpOENOdXdsNldZZ1h6aWdGdlhJIiwiYWxnIjoiRVMyNTYiLCJ0eXAiOiJ2YytzZC1qd3QifQ.eyJfc2QiOlsiZk9CVVNRdm80NnlRTy13UndYQmNHcXZuYktJdWVJU0VMOTYxX1NqZDRkbyJdLCJpc3MiOiJodHRwczovL2ludmFsaWRJc3N1ZXIuZXhhbXBsZS5jb20iLCJpYXQiOjE2ODMwMDAwMDAsImV4cCI6MjE0NzQ4MzY0NiwidmN0IjoiRmxhdCBKd3QiLCJzdWIiOiI2YzVjMGE0OS1iNTg5LTQzMWQtYmFlNy0yMTkxMjJhOWVjMmMiLCJfc2RfYWxnIjoic2hhLTI1NiJ9.j29YFdkKqfxWEEdomMO95oYNxJfhAqspwaoO9bktLcZeHuBrXaRnTeFaxX_Zz48V9MB8ieqTRJ2wy3UEk5OuMg~WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgImFkZHJlc3MiLCB7InN0cmVldF9hZGRyZXNzIjogIlNjaHVsc3RyLiAxMiIsICJsb2NhbGl0eSI6ICJTY2h1bHBmb3J0YSIsICJyZWdpb24iOiAiU2FjaHNlbi1BbmhhbHQiLCAiY291bnRyeSI6ICJERSJ9XQ~";
    
    private const string issuerJwk = "{\"kty\":\"EC\",\"use\":\"sig\",\"crv\":\"P-256\",\"kid\":\"zzeUnL35VO9Vdz_iRNGRiw89i8CNuwl6WYgXzigFvXI\",\"x\":\"xpCIuCmbmTKowucA4dddE7lZyG1ZvpAuS3ppfLwVcOE\",\"y\":\"KQVHXWH-0XEpCoH-bp9QsoWbvdWj0Q6OfADriYyjJuE\",\"alg\":\"ES256\"}";
    
    private const string validIssuer = "https://issuer.example.com";
    private readonly IHolder _holder = new Holder();

    [Test]
    public void CanCreatePresentation()
    {
        SdJwtDoc sdJwtDoc = new SdJwtDoc(sdJwtIssued);
        
        var result = _holder.CreatePresentation(sdJwtDoc.EncodedIssuerSignedJwt, new[] { sdJwtDoc.Disclosures[2] });

        Assert.NotNull(result);
        Assert.That(result, Is.EqualTo(sdJwtPresentedWithoutConfirmation));
    }
    
    [Test]
    [TestCase(validFlatJwt)]
    [TestCase(validStructuredJwt)]
    [TestCase(validRecursiveJwt)]
    [TestCase(validComplexStructuredJwt)]
    public void SuccessfullyReceiveCredential(string sdJwt)
    {
        Assert.DoesNotThrow(() => Assert.NotNull(_holder.ReceiveCredential(sdJwt, issuerJwk, validIssuer)));
    }
    
    [Test]
    [TestCase(invalidFlatJwtWithKbJwt)]
    [TestCase(invalidExpiredFlatJwt)]
    [TestCase(validFlatJwtWithInvalidSignature)]
    [TestCase(invalidFlatJwtWithRepeatingDigests)]
    [TestCase(invalidFlatJwtWithInvalidIssuer)]
    public void FailReceiveCredential(string sdJwt)
    {
        var ex = Assert.Throws<InvalidOperationException>(() => _holder.ReceiveCredential(sdJwt, issuerJwk, validIssuer));
        Assert.That(ex.Message, Does.Contain("Invalid SD-JWT - "));
    }
}