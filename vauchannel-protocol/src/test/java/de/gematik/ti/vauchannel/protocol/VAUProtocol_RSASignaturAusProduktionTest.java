/*
 * Copyright (c) 2022 gematik GmbH
 * 
 * Licensed under the Apache License, Version 2.0 (the License);
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an 'AS IS' BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.gematik.ti.vauchannel.protocol;

import static de.gematik.ti.vauchannel.protocol.helpers.ObjectMapperFactory.objectMapper;

import com.fasterxml.jackson.databind.ObjectMapper;
import de.gematik.rs.vau.VAUClientSigFin;
import de.gematik.ti.vauchannel.protocol.helpers.VAUProtocolCryptoImpl;
import de.gematik.ti.vauchannel.protocol.helpers.VAUProtocolHelpers;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Test;

public class VAUProtocol_RSASignaturAusProduktionTest {

  static {
    Security.addProvider(new BouncyCastleProvider());
  }

  @Test
  public void signaturCheck() throws Exception {
    Security.addProvider(new BouncyCastleProvider());

    String VAUCLIENTSIGFIN2 =
        "{\"Certificate\":\"MIIE6TCCA9GgAwIBAgIHARIC2HwOrTANBgkqhkiG9w0BAQsFADCBljELMAkGA1UEBhMCREUxHzAdBgNVBAMMFkdFTS5FR0stQ0EwOCBURVNULU9OTFkxHzAdBgNVBAoMFmdlbWF0aWsgR21iSCBOT1QtVkFMSUQxRTBDBgNVBAsMPEVsZWt0cm9uaXNjaGUgR2VzdW5kaGVpdHNrYXJ0ZS1DQSBkZXIgVGVsZW1hdGlraW5mcmFzdHJ1a3R1cjAeFw0xNzExMjMwMDAwMDBaFw0yMjExMjIyMzU5NTlaMIHMMTwwOgYDVQQDDDNGbG9yZXN0YW4gRG9taW5pay1QZXRlciBLLiBGcmVpaGVyciDDnHJiYW5URVNULU9OTFkxDzANBgNVBAQMBsOccmJhbjEmMCQGA1UEKgwdRmxvcmVzdGFuIERvbWluaWstUGV0ZXIgS2xhdXMxEzARBgNVBAsMClgxMTA0NzY1NjkxEjAQBgNVBAsMCTEwOTUwMDk2OTEdMBsGA1UECgwUVGVzdCBHS1YtU1ZOT1QtVkFMSUQxCzAJBgNVBAYTAkRFMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtW3EE12omIkQWON/ES87vRvje+2/A8Wek8UNn7tN3Nl/snfL16eY6i5KlKTienOhhapOqZHy1jJ3Ucc2dmD+G7Gv0txb0CbqFZDnlIr0n4GCCeb2NBwSRiPlCMuWkhcEqM6cev23fFUm+0DOTY8pUmTFHBUBVFfgnTFct+NpRFr8ZBrY84DB54tc4edr9wS5qkn4yR+i/Iln36LNmyzIABPZKDcQ2lE6+3AecoKkl5lml28n3mcjvt1bi2DD7ftAYtXH+Yn7cBzaNHh8PYKknzQ/94Vgdcqf7PDfaNWzx6npEhCVcQJEwMP4QmSyOo81TyEo+sCJpo1yFOi6YIDeRwIDAQABo4IBAjCB/zAwBgUrJAgDAwQnMCUwIzAhMB8wHTAQDA5WZXJzaWNoZXJ0ZS8tcjAJBgcqghQATAQxMCAGA1UdIAQZMBcwCgYIKoIUAEwEgSMwCQYHKoIUAEwERDAOBgNVHQ8BAf8EBAMCBDAwSwYIKwYBBQUHAQEEPzA9MDsGCCsGAQUFBzABhi9odHRwOi8vb2NzcC5wa2kudGVsZW1hdGlrLXRlc3Q6ODA4MC9DTU9DU1AvT0NTUDAdBgNVHQ4EFgQU0BpubqnRl58FeCTcCpk1YgiXcdowHwYDVR0jBBgwFoAU/vFCAppFTnXrac9nE+5WBmXOHhYwDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOCAQEAAwCEPwF2k9NXoQIc+HYyasUzo2+3d1ULnxxvi9eIaKVjSHFQEg5UYUXsm962CIh03D0jlR9y9s0hhSQZIAwrGAiZbJ+zU8HgQiRwwOBQIVrvX/NhxIz/rsWpqLzJQ0DZaIBJ8yFVWUKJ2Wf5ws634Xnh/BNFIYYL+h/sah0TLDZsUgesI/9FvSZVtR1zYsfmCSpJPkwuEAsYILj1rBMl4BDVK7GZlYg7Ebu/Ql3Vy07OJPxOwX+X7s3zzNhSJKb25Bzvsrxf7EG557oN1cYcKYRFcuy/YkcLtK0m59AhdC46MHRQyKMPWSX5sA42ri98DDJ+RFenNPuAdenltJLtHA==\",\"FinishedData\":\"MQlR30OpKLIvvkwZYnQx/04U7rw9mn9S4ZHAtukIO0b7sCD/3cqPVmDTyyXa6RSa5KQ7PHqz06AakdheZSZPg1k5fkWtaEUMtvBYKzyVzaLLHMOYEW0mEPcZQIZuJfolfyTqT+RJsoqElw7790tCTG0/zA9/uhrm7Xsthvl8t98umZNxol6dMRuwXINBQ7tNg9aTnk18Ys27OKFresLI2rNP4A==\",\"MessageType\":\"VAUClientSigFin\",\"OCSPResponse\":\"\",\"Signature\":\"KWGjxNbvoUK5xMrocpha7yCZRRP8hUe6K0WZIQYw45wDrANHGaoSCzIvGHGMG46j7dxxfZN7v+yYw0LhfMi99U1fQ1zyPNFt2bvHwUWWrYFoidGOnzm9CpeLRM+hGlyf6ORG80eOV5uCulsJpFkIM2XSpsz3kBrcl6cW5JSQJo33G1fYHJTq0Pj1BE5loQSytD8vToT6oyttMIEBtYidwi2drwseEaaO+d+0Ubs4Kj0kXrh8zUjj0sDTK0mase/VixuWghnhP35ZLwTvoYV+ixGgVbitzUYHsz9KmI57v268XEenIH28hf8SnbELxtd4Ppl0fVCiTb5PbovsbZUhcw==\",\"VAUClientHelloDataHash\":\"/L67m5kf+CSiTk27rkg43qQdUQ+Kqhk02gYDdISEYCU=\",\"VAUServerHelloDataHash\":\"dzZ5D0RsUX4mz5tRIu1LpdFPQC0XlAF1lReYw2CDWUc=\"}";

    String VAUCLIENTSIGFIN =
        "{\n"
            + "  \"Certificate\" : \"MIIE6TCCA9GgAwIBAgIHARIC2HwOrTANBgkqhkiG9w0BAQsFADCBljELMAkGA1UEBhMCREUxHzAdBgNVBAMMFkdFTS5FR0stQ0EwOCBURVNULU9OTFkxHzAdBgNVBAoMFmdlbWF0aWsgR21iSCBOT1QtVkFMSUQxRTBDBgNVBAsMPEVsZWt0cm9uaXNjaGUgR2VzdW5kaGVpdHNrYXJ0ZS1DQSBkZXIgVGVsZW1hdGlraW5mcmFzdHJ1a3R1cjAeFw0xNzExMjMwMDAwMDBaFw0yMjExMjIyMzU5NTlaMIHMMTwwOgYDVQQDDDNGbG9yZXN0YW4gRG9taW5pay1QZXRlciBLLiBGcmVpaGVyciDDnHJiYW5URVNULU9OTFkxDzANBgNVBAQMBsOccmJhbjEmMCQGA1UEKgwdRmxvcmVzdGFuIERvbWluaWstUGV0ZXIgS2xhdXMxEzARBgNVBAsMClgxMTA0NzY1NjkxEjAQBgNVBAsMCTEwOTUwMDk2OTEdMBsGA1UECgwUVGVzdCBHS1YtU1ZOT1QtVkFMSUQxCzAJBgNVBAYTAkRFMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtW3EE12omIkQWON/ES87vRvje+2/A8Wek8UNn7tN3Nl/snfL16eY6i5KlKTienOhhapOqZHy1jJ3Ucc2dmD+G7Gv0txb0CbqFZDnlIr0n4GCCeb2NBwSRiPlCMuWkhcEqM6cev23fFUm+0DOTY8pUmTFHBUBVFfgnTFct+NpRFr8ZBrY84DB54tc4edr9wS5qkn4yR+i/Iln36LNmyzIABPZKDcQ2lE6+3AecoKkl5lml28n3mcjvt1bi2DD7ftAYtXH+Yn7cBzaNHh8PYKknzQ/94Vgdcqf7PDfaNWzx6npEhCVcQJEwMP4QmSyOo81TyEo+sCJpo1yFOi6YIDeRwIDAQABo4IBAjCB/zAwBgUrJAgDAwQnMCUwIzAhMB8wHTAQDA5WZXJzaWNoZXJ0ZS8tcjAJBgcqghQATAQxMCAGA1UdIAQZMBcwCgYIKoIUAEwEgSMwCQYHKoIUAEwERDAOBgNVHQ8BAf8EBAMCBDAwSwYIKwYBBQUHAQEEPzA9MDsGCCsGAQUFBzABhi9odHRwOi8vb2NzcC5wa2kudGVsZW1hdGlrLXRlc3Q6ODA4MC9DTU9DU1AvT0NTUDAdBgNVHQ4EFgQU0BpubqnRl58FeCTcCpk1YgiXcdowHwYDVR0jBBgwFoAU/vFCAppFTnXrac9nE+5WBmXOHhYwDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOCAQEAAwCEPwF2k9NXoQIc+HYyasUzo2+3d1ULnxxvi9eIaKVjSHFQEg5UYUXsm962CIh03D0jlR9y9s0hhSQZIAwrGAiZbJ+zU8HgQiRwwOBQIVrvX/NhxIz/rsWpqLzJQ0DZaIBJ8yFVWUKJ2Wf5ws634Xnh/BNFIYYL+h/sah0TLDZsUgesI/9FvSZVtR1zYsfmCSpJPkwuEAsYILj1rBMl4BDVK7GZlYg7Ebu/Ql3Vy07OJPxOwX+X7s3zzNhSJKb25Bzvsrxf7EG557oN1cYcKYRFcuy/YkcLtK0m59AhdC46MHRQyKMPWSX5sA42ri98DDJ+RFenNPuAdenltJLtHA==\",\n"
            + "  \"FinishedData\" : \"PQKzsYBVQzJ4Xx75v5gGvZdb/5w8BcpRIblqJh3FvjzZ8Wj8/EGeVj1F0Frd5plSoArxXmDTwkDRuHdx+BDj/Qa39N96bwtRJ0hNdlsTnQnStxJbDC6roZyjXGEwRT1BrS6BNqwQ9ODggqS5xXDsYuoCvwNZ3OwMvav5hl3tAbx5P1mFq2/xnIBQ9A3VuGeKoVNNP0uW/ofC93WYb0lKbKpn8g==\",\n"
            + "  \"MessageType\" : \"VAUClientSigFin\",\n"
            + "  \"OCSPResponse\" : \"\",\n"
            + "  \"Signature\" : \"gxV+Hvhbt8FOKTKJih5Uc9RjRD7pGlbX3u8HA6NeYgrXVgUfFUwBDTdabrThK6AbuwetJQX2e4r7jy9VT2zUE1Vm5kegApEziWqrnEljduLoYajBLitsi9R1NapsYysE/ltt9GmCWnLudl6p8+kwN2jqzRwCRu4ekhEoXhm2gcSwwpOBf014Nv+ozvNEKdrHHZ/VgKS5FtLNvzEeDu6Fi7HcENYMJ2TOiLPa3+KwDhm1ZXzlyEtlReiGcHovQXcSkNOtbrIGIMVJ8gGLtV7MppnGPHHmPsEf4C5hemV5UnPgs7iniNl+yp3cR3Yz6wtyyyqL1QT6U2u0uirbUQQxgA==\",\n"
            + "  \"VAUClientHelloDataHash\" : \"yJNiMfUPzK/YObFR2Eui3B+ZylAuyRClSJms+3Qo1Ic=\",\n"
            + "  \"VAUServerHelloDataHash\" : \"gXgL5KQQVceKO2fULXi/DPTk2kz2HzxxGWrDPl2OV+o=\"\n"
            + "}";

    ObjectMapper mapper = objectMapper();
    VAUClientSigFin vAUClientSigFin = mapper.readValue(VAUCLIENTSIGFIN, VAUClientSigFin.class);

    VAUProtocolHelpers.checkClientSignature(vAUClientSigFin, new VAUProtocolCryptoImpl());

    VAUClientSigFin vAUClientSigFin2 = mapper.readValue(VAUCLIENTSIGFIN2, VAUClientSigFin.class);

    VAUProtocolHelpers.checkClientSignature(vAUClientSigFin2, new VAUProtocolCryptoImpl());
  }
}
