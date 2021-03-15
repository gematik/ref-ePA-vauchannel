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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Calendar;
import java.util.Date;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

public class KeyPairGenerator {
  public static final int KEY_SIZE = 2048;
  private static final SecureRandom SECURE_RANDOM;

  static {
    try {
      SECURE_RANDOM = SecureRandom.getInstance("SHA1PRNG");
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException("Startup exception", e);
    }

    Security.addProvider(new BouncyCastleProvider());
  }

  public static KeyPair generateRSAKeyPair()
      throws NoSuchAlgorithmException, NoSuchProviderException {
    java.security.KeyPairGenerator generator =
        java.security.KeyPairGenerator.getInstance("RSA", "BC");
    generator.initialize(KEY_SIZE, SECURE_RANDOM);

    //        logger.info("RSA key pair generated.");
    return generator.generateKeyPair();
  }

  public static KeyPair generateECCKeyPair(String spec)
      throws InvalidAlgorithmParameterException, NoSuchProviderException, NoSuchAlgorithmException {
    java.security.KeyPairGenerator kpg = java.security.KeyPairGenerator.getInstance("EC", "BC");
    ECGenParameterSpec namedParameterSpec = new ECGenParameterSpec(spec);
    kpg.initialize(namedParameterSpec, SECURE_RANDOM);
    return kpg.generateKeyPair();
  }

  public static KeyPair generateECCKeyPair()
      throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {
    return generateECCKeyPair("brainpoolp256r1");
  }

  public static X509Certificate selfSign(
      KeyPair keyPair, String subjectDN, String signatureAlgorithm)
      throws OperatorCreationException, CertificateException, IOException, NoSuchProviderException {
    Provider bcProvider = new BouncyCastleProvider();
    Security.addProvider(bcProvider);

    long now = System.currentTimeMillis();
    Date startDate = new Date(now);

    X500Name dnName = new X500Name(subjectDN);
    BigInteger certSerialNumber =
        new BigInteger(
            Long.toString(now)); // <-- Using the current timestamp as the certificate serial number

    Calendar calendar = Calendar.getInstance();
    calendar.setTime(startDate);
    calendar.add(Calendar.YEAR, 1); // <-- 1 Yr validity

    Date endDate = calendar.getTime();

    //  String signatureAlgorithm = "SHA256WithRSA"; // <-- Use appropriate signature algorithm
    // based on your keyPair algorithm.

    ContentSigner contentSigner =
        new JcaContentSignerBuilder(signatureAlgorithm).build(keyPair.getPrivate());

    JcaX509v3CertificateBuilder certBuilder =
        new JcaX509v3CertificateBuilder(
            dnName, certSerialNumber, startDate, endDate, dnName, keyPair.getPublic());

    // Extensions --------------------------
    // Basic Constraints
    //  BasicConstraints basicConstraints = new BasicConstraints(true); // <-- true for CA, false
    // for EndEntity

    //  certBuilder.addExtension(new ASN1ObjectIdentifier("2.5.29.19"), true, basicConstraints); //
    // Basic Constraints is usually marked as critical.

    // -------------------------------------

    X509CertificateHolder h = certBuilder.build(contentSigner);

    Certificate c = new JcaX509CertificateConverter().setProvider(bcProvider).getCertificate(h);

    CertificateFactory certFactory =
        CertificateFactory.getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME);
    InputStream in = new ByteArrayInputStream(c.getEncoded());
    return (X509Certificate) certFactory.generateCertificate(in);
  }

  public static X509Certificate generateCertificate(
      KeyPair keyPair, String subjectDN, String signatureAlgorithm) throws Exception {
    Date NOT_BEFORE = new Date();
    Calendar NOT_AFTER = Calendar.getInstance();
    NOT_AFTER.add(Calendar.YEAR, 100);
    X500Name subjectAndIssuer = new X500Name("CN=peercentrum node");
    X509v3CertificateBuilder certificateBuilder =
        new JcaX509v3CertificateBuilder(
            subjectAndIssuer,
            new BigInteger("42"),
            NOT_BEFORE,
            NOT_AFTER.getTime(),
            subjectAndIssuer,
            keyPair.getPublic());

    final DLSequence extension =
        new DLSequence(
            new DLSequence(
                new DLSequence(
                    new DLSequence(
                        new DLSequence(
                            new ASN1Encodable[] {
                              new DLSequence(
                                  new DERUTF8String("ePA vertrauenswürdige Ausführungsumgebung")),
                              new DLSequence(new ASN1ObjectIdentifier("1.2.276.0.76.4.209"))
                            })))));

    certificateBuilder.addExtension(new ASN1ObjectIdentifier("1.3.36.8.3.3"), false, extension);

    ContentSigner signer =
        new JcaContentSignerBuilder("SHA256withECDSA")
            .setProvider("BC")
            .build(keyPair.getPrivate());
    X509CertificateHolder certHolder = certificateBuilder.build(signer);
    return new JcaX509CertificateConverter().setProvider("BC").getCertificate(certHolder);
  }
}
