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
import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.*;
import java.util.Enumeration;

/**
 * @author matthias.unverzagt
 */
public class KeyProvider {

  public static X509Certificate getCertificate2(String p12Password, String p12Path)
      throws Exception {
    KeyStore p12 = KeyStore.getInstance("pkcs12", "BC");
    p12.load(new FileInputStream(p12Path), p12Password.toCharArray());
    X509Certificate c = null;
    Enumeration e = p12.aliases();
    while (e.hasMoreElements()) {
      String alias = (String) e.nextElement();
      c = (X509Certificate) p12.getCertificate(alias);
    }
    return c;
  }

  public static PrivateKey getPrivateKey2(
      String p12Password, String privateKeyPassword, String p12Path) throws Exception {
    KeyStore p12 = KeyStore.getInstance("pkcs12", "BC");
    p12.load(new FileInputStream(p12Path), p12Password.toCharArray());
    PrivateKey privateKey = null;
    Enumeration e = p12.aliases();
    while (e.hasMoreElements()) {
      String alias = (String) e.nextElement();
      privateKey = (PrivateKey) p12.getKey(alias, privateKeyPassword.toCharArray());
    }

    return privateKey;
  }

  public static Identity getIdentity(String p12Password, String privateKeyPassword, String p12Path)
      throws Exception {
    KeyStore p12 = KeyStore.getInstance("pkcs12", "BC");
    p12.load(new FileInputStream(p12Path), p12Password.toCharArray());
    Identity identity = null;
    Enumeration e = p12.aliases();
    while (e.hasMoreElements()) {
      String alias = (String) e.nextElement();
      X509Certificate c = (X509Certificate) p12.getCertificate(alias);
      PrivateKey privateKey = (PrivateKey) p12.getKey(alias, privateKeyPassword.toCharArray());
      identity = new Identity(privateKey, c);
    }

    return identity;
  }

  public static Identity getIdentity(byte[] p12Bytes, String p12Password, String privateKeyPassword)
      throws KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException, IOException,
          CertificateException, NoSuchProviderException {
    KeyStore p12 = KeyStore.getInstance("pkcs12", "BC");
    p12.load(new ByteArrayInputStream(p12Bytes), p12Password.toCharArray());
    Identity identity = null;
    Enumeration e = p12.aliases();
    while (e.hasMoreElements()) {
      String alias = (String) e.nextElement();
      X509Certificate c = (X509Certificate) p12.getCertificate(alias);
      PrivateKey privateKey = (PrivateKey) p12.getKey(alias, privateKeyPassword.toCharArray());
      identity = new Identity(privateKey, c);
    }
    return identity;
  }
}
