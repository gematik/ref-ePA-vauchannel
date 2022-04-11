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
package de.gematik.ti.vauchannel.protocol.helpers;

import static org.junit.Assert.*;

import de.gematik.ti.vauchannel.protocol.VAUProtocolCrypto;
import org.junit.Test;

public class VAUProtocolHelpersTest {

  @Test
  public void checkClientCertificateHashExample() {
    VAUProtocolCrypto crypto = new VAUProtocolCryptoImpl();
    String certStr =
        "MIIE0zCCA7ugAwIBAgIHA6HPW6yhzjANBgkqhkiG9w0BAQsFADCBljELMAkGA1UEBhMCREUxHzAdBgNVBAoMFmdlbWF0aWsgR21iSCBOT1QtVkFMSUQxRTBDBgNVBAsMPEVsZWt0cm9uaXNjaGUgR2VzdW5kaGVpdHNrYXJ0ZS1DQSBkZXIgVGVsZW1hdGlraW5mcmFzdHJ1a3R1cjEfMB0GA1UEAwwWR0VNLkVHSy1DQTI0IFRFU1QtT05MWTAeFw0xOTExMTkwMDAwMDBaFw0yNDExMTgyMzU5NTlaMIHKMQswCQYDVQQGEwJERTEdMBsGA1UECgwUVGVzdCBHS1YtU1ZOT1QtVkFMSUQxEzARBgNVBAsMClgxMTA0NjE1OTMxEjAQBgNVBAsMCTEwOTUwMDk2OTESMBAGA1UEBAwJQsO2ZGVmZWxkMSUwIwYDVQQqDBxLcmllbWhpbGQgQWRlbGUgRnJlaWZyYXUgdm9uMTgwNgYDVQQDDC9LcmllbWhpbGQgQWRlbGUgRnJlaWZyYXUgdm9uIELDtmRlZmVsZFRFU1QtT05MWTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJ8Hm7z2kiHDbHHkByu0WLCqyfteSfaaU9Zi4ROytu7vumWrp1GZ9qWgUsLdWffLIHdvSLADgdP3qM9vohNNpzFKGn0srW2fCEffT++KD+HQcKU+Ue/+aKXBSTBgAh4FILCTcrzkM2lo5BLKTaEDP18QEL/ix1NOSZ/UmuTTPjQ9Z7SbmiGAKtIjpo3Mj4RSZkmBmSBZNVQRa0a7H3sMI2/JNboZQAhJXOHEx+szlX630lt81oKL2SVLNySgXuB2xHPjvoxdwWuzBRG7nt+YsKiG7Ek+URc49uEgQsws/g1l0LDJES3SGBhAT4zYqLLz3m6ocWfkqKoXMBDDb4jMfDMCAwEAAaOB7zCB7DAgBgNVHSAEGTAXMAoGCCqCFABMBIEjMAkGByqCFABMBEYwHQYDVR0OBBYEFGNeEtzc3OnqTOyPRE7hGRzjrI/UMB8GA1UdIwQYMBaAFLCindo7Cxxs8/GesHU2gHHrpbChMDAGBSskCAMDBCcwJTAjMCEwHzAdMBAMDlZlcnNpY2hlcnRlLy1yMAkGByqCFABMBDEwDAYDVR0TAQH/BAIwADA4BggrBgEFBQcBAQQsMCowKAYIKwYBBQUHMAGGHGh0dHA6Ly9laGNhLmdlbWF0aWsuZGUvb2NzcC8wDgYDVR0PAQH/BAQDAgeAMA0GCSqGSIb3DQEBCwUAA4IBAQA16Ouy09EB2B+aHFgWY1RX10ygaiWefXk2dNemUm9DsZI0faPxuRuzhW0rtZrKAb2HEMoks4rcRz365NB9AlMRTmAxfm+Pr8ab/sff1byWWo0b/xEuM5H0UoHyG9ZL5xcaPkwlUJ0bZOlIkM4l76yr4CHeTWSAEgYhLB1mF817TFVdEG/nYc2Ul2aeAdVkHuPnRuBP2REGDdlDQJKtocRVh2GnwXyUUf8gZgHHe+FnkSCKAPfqwh3aZEhQj/1U1dd2jXeyFmUzrJQQF758vc8V82ejvBFWxGvhZIePvEj3HpEvzq0iowhce9LOqloETwKC36nnDOiexRKT72VWPQxX";
    System.out.println(Base64.encode2String(crypto.hash(Base64.decode(certStr))));
  }
}
