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

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import org.apache.commons.io.FileUtils;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

public class OCSPResponseGeneratorTest {

  private static final String OCSP_IDENTITY = "src/test/resources/ocsp/vau_ocsp_identity.p12";

  @BeforeClass
  public static void beforeClass() {
    Security.addProvider(new BouncyCastleProvider());
  }

  @Test
  public void expectOcspResponseGeneratorWorksAsExpected() {
    try {
      final String serverIdentityPath = "src/test/resources/identity/vau_server_identity.p12";
      final Identity serverIdentity = loadIdentityFromKeystore(serverIdentityPath);
      Assert.assertNotNull(serverIdentity.certificate);

      final Identity ocspSignerIdentity = loadIdentityFromKeystore(OCSP_IDENTITY);
      Assert.assertNotNull(ocspSignerIdentity.certificate);
      Assert.assertNotNull(ocspSignerIdentity.privateKey);

      final var response =
          OCSPResponseGenerator.gen(
              serverIdentity.certificate,
              loadIssuerCertificate(serverIdentityPath),
              ocspSignerIdentity.certificate,
              ocspSignerIdentity.privateKey,
              CertificateStatus.GOOD);

      Assert.assertNotNull(response);
      Assert.assertNotNull(response.toASN1Structure().getResponseStatus());
      Assert.assertNotNull(response.toASN1Structure().getResponseBytes().getResponseType().getId());
      Assert.assertEquals(OCSPResp.SUCCESSFUL, response.getStatus());
      Assert.assertTrue(
          "1.3.6.1.5.5.7.48.1.1"
              .contentEquals(
                  response.toASN1Structure().getResponseBytes().getResponseType().getId()));
    } catch (Exception exception) {
      Assert.fail(exception.getMessage());
    }
  }

  private Identity loadIdentityFromKeystore(final String p12Filename) throws Exception {
    return KeyProvider.getIdentity("00", "00", p12Filename);
  }

  private X509Certificate loadIssuerCertificate(final String p12Filename) throws IOException {
    try (final var certList = Files.list(Path.of(p12Filename).getParent())) {
      final var validPath =
          certList
              .filter(path -> path.toString().endsWith(".pem"))
              .filter(path -> path.toString().contains("-CA"))
              .findAny();
      if (validPath.isPresent()) {
        return getCertificate(
            FileUtils.readFileToByteArray(new File(String.valueOf(validPath.get()))));
      }
    }

    throw new IllegalArgumentException("Could not find a valid Certificate Path");
  }

  private X509Certificate getCertificate(final byte[] crt) {
    try {
      CertificateFactory certFactory =
          CertificateFactory.getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME);
      InputStream in = new ByteArrayInputStream(crt);
      X509Certificate x509Certificate = (X509Certificate) certFactory.generateCertificate(in);
      if (x509Certificate == null) {
        throw new IllegalArgumentException("Error while loading certificate!");
      } else {
        return x509Certificate;
      }
    } catch (RuntimeException var4) {
      throw var4;
    } catch (Exception var5) {
      throw new IllegalArgumentException("Error while loading certificate!", var5);
    }
  }
}
