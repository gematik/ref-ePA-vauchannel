/*
 * Copyright (c) 2020 gematik GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the
 * License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.
 */
package de.gematik.ti.vauchannel.protocol.helpers;

import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.ZonedDateTime;
import java.util.Date;
import org.apache.commons.codec.digest.DigestUtils;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.isismtt.ocsp.CertHash;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.BasicOCSPRespBuilder;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

public class OCSPResponseGenerator {

  private static final AlgorithmIdentifier SHA256_OID =
      new AlgorithmIdentifier(new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.1"));

  public static OCSPResp gen(
      final X509Certificate eeCertJca,
      final X509Certificate caCertJca,
      final X509Certificate ocspSignerCertJa,
      final PrivateKey ocspSignerPrivateKey,
      final CertificateStatus status)
      throws CertificateException {
    return gen(
        eeCertJca, caCertJca, ocspSignerCertJa, ocspSignerPrivateKey, status, ZonedDateTime.now());
  }

  public static OCSPResp gen(
      final X509Certificate eeCertJca,
      final X509Certificate caCertJca,
      final X509Certificate ocspSignerCertJa,
      final PrivateKey ocspSignerPrivateKey,
      final CertificateStatus status,
      final ZonedDateTime dateTime)
      throws CertificateException {
    try {
      X509CertificateHolder caCertificate = new JcaX509CertificateHolder(caCertJca);

      DigestCalculatorProvider digCalcProv = new BcDigestCalculatorProvider();
      BasicOCSPRespBuilder basicBuilder =
          new BasicOCSPRespBuilder(
              SubjectPublicKeyInfo.getInstance(ocspSignerCertJa.getPublicKey().getEncoded()),
              digCalcProv.get(CertificateID.HASH_SHA1));

      CertificateID certId =
          new CertificateID(
              digCalcProv.get(CertificateID.HASH_SHA1), caCertificate, eeCertJca.getSerialNumber());

      byte[] certHash = DigestUtils.sha256(eeCertJca.getEncoded());
      Extensions singleResponseExtensions =
          new Extensions(
              new Extension(
                  new ASN1ObjectIdentifier("1.3.36.8.3.13"),
                  false,
                  new CertHash(SHA256_OID, certHash).toASN1Primitive().getEncoded()));

      Date updateDate = new Date();
      if (status != CertificateStatus.GOOD) {
        updateDate = new Date(updateDate.getTime() - 60000);
      }

      basicBuilder.addResponse(certId, status, updateDate, null, singleResponseExtensions);

      X509CertificateHolder[] chain = {new X509CertificateHolder(ocspSignerCertJa.getEncoded())};
      BasicOCSPResp resp =
          basicBuilder.build(
              new JcaContentSignerBuilder("SHA256withECDSA")
                  .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                  .build(ocspSignerPrivateKey),
              chain,
              new Date(dateTime.toInstant().toEpochMilli()));

      OCSPRespBuilder builder = new OCSPRespBuilder();
      return builder.build(OCSPRespBuilder.SUCCESSFUL, resp);
    } catch (Exception e) {
      throw new CertificateException("cannot generate OCSP response", e);
    }
  }
}
