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

import static de.gematik.ti.vauchannel.protocol.helpers.Identity.generateSelfSigned_ECC;
import static de.gematik.ti.vauchannel.protocol.helpers.Identity.generateSelfSigned_RSA;
import static de.gematik.ti.vauchannel.protocol.helpers.VAUProtocolHelpers.checkVauServerCertificateExtension;

import de.gematik.ti.vauchannel.protocol.VAUProtocolCrypto;
import de.gematik.ti.vauchannel.protocol.VAUProtocolSession;
import java.io.IOException;
import java.security.*;
import java.security.cert.*;
import java.security.spec.X509EncodedKeySpec;
import java.time.LocalDateTime;
import javax.crypto.KeyAgreement;
import org.bouncycastle.asn1.*;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

// an example implementation
public class VAUProtocolCryptoImpl implements VAUProtocolCrypto {

  private static final Logger logger = LoggerFactory.getLogger(VAUProtocolCryptoImpl.class);

  static {
    Security.addProvider(new BouncyCastleProvider());
  }

  boolean doValidateAuthorizationAssertion;
  boolean ecc;
  private Identity eeIdentity;
  private Identity ocspSignerIdentity;
  private X509Certificate caCertificate;

  public VAUProtocolCryptoImpl(boolean ecc) {
    this.ecc = ecc;
    try {
      if (ecc) {
        this.eeIdentity = generateSelfSigned_ECC();
      } else {
        this.eeIdentity = generateSelfSigned_RSA();
      }
    } catch (Exception ex) {
      logger.error(ex.getMessage(), ex);
    }
  }

  public VAUProtocolCryptoImpl() {
    this(false, null, null, null);
  }

  public VAUProtocolCryptoImpl(final boolean ecc, final Identity eeIdentity) {
    this(ecc, eeIdentity, null, null);
  }

  public VAUProtocolCryptoImpl(
      final boolean ecc,
      final Identity eeIdentity,
      final X509Certificate caCertificate,
      final Identity ocspSignerIdentity) {
    this(false, ecc, eeIdentity, caCertificate, ocspSignerIdentity);
  }

  public VAUProtocolCryptoImpl(
      final boolean doValidateAuthorizationAssertion,
      final boolean ecc,
      final Identity eeIdentity,
      final X509Certificate caCertificate,
      final Identity ocspSignerIdentity) {
    this.doValidateAuthorizationAssertion = doValidateAuthorizationAssertion;
    this.ecc = ecc;
    this.eeIdentity = eeIdentity;
    this.caCertificate = caCertificate;
    this.ocspSignerIdentity = ocspSignerIdentity;
  }

  @Override
  public LocalDateTime now() {
    return LocalDateTime.now();
  }

  public byte[] hash(byte[] in) {
    MessageDigest sha;
    byte[] out;
    try {
      sha = MessageDigest.getInstance("SHA-256");
      sha.update(in);
      out = sha.digest();
    } catch (NoSuchAlgorithmException ex) {
      logger.error(ex.getMessage(), ex);
      throw new RuntimeException("internal vau protocol exception");
    }
    return out;
  }

  public byte[] ECKA(PrivateKey prk, PublicKey puk) throws Exception {
    byte[] sharedSecret;
    KeyAgreement ka = KeyAgreement.getInstance("ECDH", "BC");
    ka.init(prk);
    ka.doPhase(puk, true);
    sharedSecret = ka.generateSecret();
    return sharedSecret;
  }

  public byte[] HKDF(byte[] ikm, String info, int length)
      throws IllegalArgumentException, DataLengthException {
    return HKDF(ikm, info.getBytes(), length);
  }

  public byte[] HKDF(byte[] ikm, byte[] info, int length)
      throws IllegalArgumentException, DataLengthException {
    HKDFBytesGenerator hkdf = new HKDFBytesGenerator(new SHA256Digest());
    hkdf.init(new HKDFParameters(ikm, null, info));
    byte[] okm = new byte[length / 8];
    hkdf.generateBytes(okm, 0, length / 8);
    return okm;
  }

  public boolean verify(byte[] message, byte[] signatureBytes, PublicKey puk) {
    try {
      return verifyECDSA(message, signatureBytes, puk);
    } catch (Exception eA) {
      try {
        return verifyRSASSA_PSS(message, signatureBytes, puk);
      } catch (Exception eB) {
        logger.error("verify not successful:");
        logger.error(eA.getMessage(), eA);
        logger.error(eB.getMessage(), eB);
      }
    }
    return false;
  }

  private boolean verifyRSASSA_PSS(byte[] message, byte[] signatureBytes, PublicKey puk)
      throws Exception {
    Signature signer = Signature.getInstance("SHA256withRSAAndMGF1", "BC");
    signer.initVerify(puk);
    signer.update(message);
    return signer.verify(signatureBytes);
  }

  private boolean verifyECDSA(byte[] message, byte[] signatureBytes, PublicKey puk)
      throws Exception {
    Signature signer = Signature.getInstance("SHA256withECDSA", "BC");
    signer.initVerify(puk);
    signer.update(message);
    return signer.verify(signatureBytes);
  }

  private byte[] signRSASSA_PSS(byte[] message, PrivateKey prk) throws Exception {
    String algorithm = "SHA256withRSAAndMGF1";
    return sign(message, prk, algorithm);
  }

  private byte[] sign(byte[] message, PrivateKey prk, String algorithm)
      throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException,
          SignatureException, IOException {
    return plainSignature(message, prk, algorithm);
  }

  private byte[] plainSignature(byte[] message, PrivateKey prk, String algorithm)
      throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException,
          SignatureException {
    Signature signer = Signature.getInstance(algorithm, "BC");
    signer.initSign(prk);
    signer.update(message);
    return signer.sign();
  }

  private byte[] signECDSA(byte[] message, PrivateKey prk) throws Exception {
    return sign(message, prk, "SHA256withECDSA");
  }

  @Override
  public byte[] signRSASSA_PSS(byte[] message) throws Exception {
    return signRSASSA_PSS(message, this.eeIdentity.privateKey);
  }

  @Override
  public byte[] signECDSA(byte[] message) throws Exception {

    return signECDSA(message, eeIdentity.privateKey);
  }

  @Override
  public KeyPair generateECCKeyPair() {
    try {
      return KeyPairGenerator.generateECCKeyPair();
    } catch (Exception e) {
      logger.error(e.getMessage(), e);
      throw new RuntimeException("internal vau protocol exception");
    }
  }

  @Override
  public PublicKey eccPublicKeyFromBytes(byte[] pubKey) {
    try {
      return KeyFactory.getInstance("ECDSA", "BC").generatePublic(new X509EncodedKeySpec(pubKey));
    } catch (Exception e) {
      logger.error(e.getMessage(), e);
      throw new RuntimeException("internal vau protocol exception");
    }
  }

  @Override
  public OCSPResp getOcspResponse() {
    try {
      return OCSPResponseGenerator.gen(
          eeIdentity.certificate,
          caCertificate,
          ocspSignerIdentity.certificate,
          ocspSignerIdentity.privateKey,
          CertificateStatus.GOOD);
    } catch (CertificateException e) {
      logger.error(e.getMessage(), e);
      throw new RuntimeException("internal vau protocol exception");
    }
  }

  @Override
  public X509Certificate getEECertificate() {
    return eeIdentity.certificate;
  }

  @Override
  public boolean isECCIdentity() {
    return ecc;
  }

  @Override
  public boolean canProvideOcspResponse() {
    return this.ocspSignerIdentity != null;
  }

  @Override
  public byte[] encrypt_AESGCM(byte[] plain, byte[] symKey, long counter) throws Exception {
    return AESGCM.encrypt(plain, symKey, counter);
  }

  @Override
  public byte[] decrypt_AESGCM(byte[] encrypted, byte[] symKey, long counter) throws Exception {
    return AESGCM.decrypt(encrypted, symKey);
  }

  @Override
  public void validateAuthorizationAssertion(
      VAUProtocolSession vauProtocolSession, String authorizationAssertionStr) {
    // needs to be implemented in an inherited class
  }

  @Override
  // Prüfung analog zu gemSpec_FdV A_15873
  public void checkServerCertificate(X509Certificate cert) {
    try {
      // Punkt 1
      cert.checkValidity();

      // Punkt 2
      performTslCheckForCertificate(cert);

      // Punkt 3 und 4
      checkVauServerCertificateExtension(cert);

      // Punkt 5
      performOcspCheckForCertificate(cert);

      // Prüfungen nach Punkt 6 sind nicht implementiert
    } catch (Exception e) {
      throw new RuntimeException("Error while verifying vau-server-certificate", e);
    }
  }

  @Override
  public void performOcspCheckForCertificate(X509Certificate cert) throws Exception {
    // Es findet keine OCSP Prüfung statt
  }

  @Override
  public void performTslCheckForCertificate(X509Certificate cert) throws Exception {
    // Es findet keine TSL Prüfung statt
  }
}
