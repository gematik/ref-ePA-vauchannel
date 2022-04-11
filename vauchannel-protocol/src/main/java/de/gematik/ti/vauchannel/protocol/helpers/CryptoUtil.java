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

import java.io.*;
import java.net.URL;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CryptoUtil {

  private static final Logger logger = LoggerFactory.getLogger(CryptoUtil.class);

  public static X509Certificate readX509CertificateDER(URL url) throws IOException {
    InputStream is = null;
    try {
      is = url.openStream();
      CertificateFactory fact =
          CertificateFactory.getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME);
      return (X509Certificate) fact.generateCertificate(is);
    } catch (CertificateException | NoSuchProviderException e) {
      throw new RuntimeException("Cannot Create X.509 Factory. Major problem.", e);
    } finally {
      if (is != null) {
        is.close();
      }
    }
  }

  public static X509Certificate readX509CertificatePEM(String pem) throws IOException {
    PemReader reader = new PemReader(new StringReader(pem));
    PemObject pemObject = reader.readPemObject();

    try {
      CertificateFactory certFactory =
          CertificateFactory.getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME);
      return (X509Certificate)
          certFactory.generateCertificate(new ByteArrayInputStream(pemObject.getContent()));
    } catch (CertificateException | NoSuchProviderException e) {
      throw new RuntimeException("Cannot Create X.509 Factory. Major problem.", e);
    }
  }

  public static X509Certificate readX509CertificatePEM(URL url) throws IOException {
    InputStream inStream = null;
    PemReader reader = null;
    try {
      inStream = url.openStream();
      reader = new PemReader(new InputStreamReader(inStream));
      PemObject pemObject = reader.readPemObject();
      CertificateFactory certFactory =
          CertificateFactory.getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME);
      return (X509Certificate)
          certFactory.generateCertificate(new ByteArrayInputStream(pemObject.getContent()));
    } catch (CertificateException | NoSuchProviderException e) {
      throw new RuntimeException("Cannot Create X.509 Factory. Major problem.", e);
    } finally {
      if (reader != null) {
        reader.close();
      }
      if (inStream != null) {
        inStream.close();
      }
    }
  }

  public static X509Certificate readX509CertificateByteArray(byte[] encodedCertificate) {
    try {
      CertificateFactory certFactory =
          CertificateFactory.getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME);
      return (X509Certificate)
          certFactory.generateCertificate(new ByteArrayInputStream(encodedCertificate));
    } catch (Exception e) {
      throw new RuntimeException("Exception while reading X509 certificate from byte array", e);
    }
  }

  public static PrivateKey readPrivateKeyDER(URL url) throws IOException {
    ByteArrayOutputStream buffer = new ByteArrayOutputStream();

    InputStream is = null;
    try {
      is = url.openStream();
      int len;
      byte[] bytes = new byte[1024];

      while ((len = is.read(bytes, 0, bytes.length)) != -1) {
        buffer.write(bytes, 0, len);
      }

      byte[] der = buffer.toByteArray();

      PKCS8EncodedKeySpec encodedKeySpec = new PKCS8EncodedKeySpec(der);
      try {
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(encodedKeySpec);
      } catch (InvalidKeySpecException e) {
        throw new IOException("Invalid key data", e);
      } catch (NoSuchAlgorithmException e) {
        throw new RuntimeException("Cannot Create X.509 Factory. Major problem.", e);
      }
    } catch (IOException ioex) {
      throw new IOException(ioex);
    } finally {
      if (is != null) {
        is.close();
      }
    }
  }

  public static PrivateKey readPrivateKeyPEM(URL url) throws IOException {

    InputStream inStream = null;
    PemReader reader = null;
    try {
      inStream = url.openStream();
      reader = new PemReader(new InputStreamReader(inStream));
      PemObject pemObject = reader.readPemObject();

      final PKCS8EncodedKeySpec encodedKeySpec = new PKCS8EncodedKeySpec(pemObject.getContent());
      try {
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(encodedKeySpec);
      } catch (InvalidKeySpecException e) {
        throw new IOException("Invalid key data", e);
      } catch (NoSuchAlgorithmException e) {
        throw new RuntimeException("Cannot Create X.509 Factory. Major problem.", e);
      }
    } catch (IOException ioex) {
      throw new IOException(ioex);
    } finally {
      if (reader != null) {
        reader.close();
      }
      if (inStream != null) {
        inStream.close();
      }
    }
  }

  //    public static byte[] prepareHash(DigestAlgorithm digestAlgorithm, byte[] hash) throws
  // IOException {
  //        DigestAlgorithmIdentifierFinder finder = new DefaultDigestAlgorithmIdentifierFinder();
  //        DigestInfo digestInfo = new DigestInfo(finder.find(digestAlgorithm.getAlgorithmName()),
  // hash);
  //        return digestInfo.getEncoded();
  //    }

  public enum DigestAlgorithm {
    SHA256("SHA-256"),
    SHA384("SHA-384"),
    SHA512("SHA-512");
    private String algorithmName;

    DigestAlgorithm(String algorithmName) {
      this.algorithmName = algorithmName;
    }

    public String getAlgorithmName() {
      return algorithmName;
    }
  }
}
