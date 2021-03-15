/*
Copyright (c) 2020 gematik GmbH

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package de.gematik.ti.vauchannel.protocol.helpers;

import static de.gematik.ti.vauchannel.protocol.helpers.KeyPairGenerator.generateCertificate;
import static de.gematik.ti.vauchannel.protocol.helpers.KeyPairGenerator.selfSign;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** @author matth */
public class Identity {
  private static final Logger logger = LoggerFactory.getLogger(Identity.class);
  public PrivateKey privateKey;
  public X509Certificate certificate;

  public Identity(PrivateKey privateKey, X509Certificate certificate) {
    this.privateKey = privateKey;
    this.certificate = certificate;
  }

  public static Identity generateSelfSigned_ECC() {
    Identity identity = null;
    try {
      KeyPair keyPair = KeyPairGenerator.generateECCKeyPair();
      X509Certificate cert =
          generateCertificate(keyPair, "CN=SelfSignedECCCertificate", "SHA256withECDSA");
      identity = new Identity(keyPair.getPrivate(), cert);
    } catch (Exception e) {
      logger.error(e.getMessage(), e);
    }
    return identity;
  }

  public static Identity generateSelfSigned_RSA() throws Exception {
    Identity identity = null;
    try {
      KeyPair keyPair = KeyPairGenerator.generateRSAKeyPair();
      X509Certificate cert = selfSign(keyPair, "CN=SelfSignedECCCertificate", "SHA256withRSA");
      identity = new Identity(keyPair.getPrivate(), cert);
    } catch (Exception e) {
      logger.error(e.getMessage(), e);
    }
    return identity;
  }
}
