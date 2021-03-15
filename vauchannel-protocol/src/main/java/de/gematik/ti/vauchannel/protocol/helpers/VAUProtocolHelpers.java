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

import static de.gematik.ti.vauchannel.protocol.helpers.ObjectMapperFactory.objectMapper;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import de.gematik.rs.vau.*;
import de.gematik.ti.vauchannel.protocol.VAUProtocolCrypto;
import de.gematik.ti.vauchannel.protocol.VAUProtocolSession;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class VAUProtocolHelpers {

  static final Logger logger = LoggerFactory.getLogger(VAUProtocolHelpers.class);
  private static final String OID_EPA_VAU = "1.2.276.0.76.4.209";
  static ObjectMapper mapper = objectMapper();

  public static List<CipherConfiguration> getCipherConfiguration() {
    List<CipherConfiguration> cipherConfiguration = new ArrayList<>();
    cipherConfiguration.add(CipherConfiguration.AES_256_GCM_BRAINPOOL_P_256_R_1_SHA_256);
    return cipherConfiguration;
  }

  public static List<CipherConfiguration_> getCipherConfiguration_() {
    List<CipherConfiguration_> cipherConfiguration = new ArrayList<>();
    cipherConfiguration.add(CipherConfiguration_.AES_256_GCM_BRAINPOOL_P_256_R_1_SHA_256);
    return cipherConfiguration;
  }

  public static void checkClientSignature(
      VAUClientSigFin vAUClientSigFin, VAUProtocolCrypto crypto) {
    boolean signatureOk;
    try {
      logger.info("ClientSignature: " + vAUClientSigFin.getSignature());

      byte[] signature = Base64.decode(vAUClientSigFin.getSignature());

      byte[] message =
          concat(
              vAUClientSigFin.getVAUClientHelloDataHash().getBytes(StandardCharsets.UTF_8),
              vAUClientSigFin.getVAUServerHelloDataHash().getBytes(StandardCharsets.UTF_8));

      byte[] certBytes = Base64.decode(vAUClientSigFin.getCertificate());
      CertificateFactory certFactory =
          CertificateFactory.getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME);

      InputStream in = new ByteArrayInputStream(certBytes);
      X509Certificate cert = (X509Certificate) certFactory.generateCertificate(in);
      PublicKey pk = cert.getPublicKey();

      signatureOk = crypto.verify(message, signature, pk);

    } catch (Exception e) {
      logger.error(e.getMessage(), e);
      throw new RuntimeException("Exception");
    }

    if (!signatureOk) {
      // Falls die Signaturprüfung ein nicht-positives Prüferergebnis liefert, so MUSS der Server
      // mit einer VAUServerError-Nachricht mit der Fehlermeldung "Signature from VAUClientSigFin
      // invalid"
      // antworten und die weitere Protokolldurchführung abbrechen.
      throw new RuntimeException("Signature from VAUClientSigFin invalid");
    }
  }

  public static void checkServerSignature(VAUServerHello vAUServerHello, VAUProtocolCrypto crypto) {
    boolean signatureOk;
    try {
      logger.info("ServerSignature: " + vAUServerHello.getSignature());

      byte[] signature = Base64.decode(vAUServerHello.getSignature());

      byte[] message = vAUServerHello.getData().getBytes(StandardCharsets.UTF_8);

      byte[] certBytes = Base64.decode(vAUServerHello.getCertificate());
      CertificateFactory certFactory =
          CertificateFactory.getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME);

      InputStream in = new ByteArrayInputStream(certBytes);
      X509Certificate cert = (X509Certificate) certFactory.generateCertificate(in);
      PublicKey pk = cert.getPublicKey();

      crypto.checkServerCertificate(cert);

      signatureOk = crypto.verify(message, signature, pk);
    } catch (CertificateException | NoSuchProviderException e) {
      throw new RuntimeException("Error during server-signature check", e);
    }

    if (!signatureOk) {
      throw new RuntimeException("Signature from VAUServerHello invalid");
    }
  }

  // Prüfung analog zu gemSpec_FdV A_15873
  private static void checkServerCertificate(X509Certificate cert, VAUProtocolCrypto crypto) {
    try {
      // Punkt 1
      cert.checkValidity();

      // Punkt 3 und 4
      checkVauServerCertificateExtension(cert);

      // Punkt 5
      crypto.checkServerCertificate(cert);

      // Prüfungen nach Punkt 6 sind nicht implementiert
    } catch (Exception e) {
      throw new RuntimeException("VAUServerCertificate not valid", e);
    }
  }

  public static void checkVauServerCertificateExtension(X509Certificate cert)
      throws CertificateEncodingException {
    final ASN1Encodable parsedValue =
        Certificate.getInstance(cert.getEncoded())
            .getTBSCertificate()
            .getExtensions()
            .getExtension(new ASN1ObjectIdentifier("1.3.36.8.3.3"))
            .getParsedValue();

    DLSequence a = (DLSequence) parsedValue;
    DLSequence b = (DLSequence) a.getObjectAt(0);
    DLSequence c = (DLSequence) b.getObjectAt(0);
    DLSequence d = (DLSequence) c.getObjectAt(0);
    DLSequence e = (DLSequence) d.getObjectAt(0);
    DLSequence f = (DLSequence) e.getObjectAt(1);
    ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier) f.getObjectAt(0);

    if (!oid.getId().equals(OID_EPA_VAU)) {
      throw new RuntimeException("Invalid extension detected: " + oid.getId());
    }
  }

  public static void checkFinishedDataFromClient(
      VAUProtocolSession serverSession,
      VAUClientSigFin vAUClientSigFin,
      byte[] expectedVauClientHelloDataHash,
      byte[] expectedVauServerHelloDataHash) {
    // Falls die Prüfung des "FinishedData"-Feld ein nicht-positives Prüferergebnis liefert,
    // so MUSS der Server mit einer VAUServerError-Nachricht mit der Fehlermeldung
    // "VAUClientSigFin invalid" antworten und die weitere Protokolldurchführung abbrechen.
    String errorMessage = "VAUClientSigFin invalid";
    byte[] finishedDataBytes = Base64.decode(vAUClientSigFin.getFinishedData());
    byte[] keyidOnServer = serverSession.getKeyID();
    byte[] keyidFromClient = new byte[keyidOnServer.length];
    System.arraycopy(finishedDataBytes, 0, keyidFromClient, 0, keyidOnServer.length);
    if (!Arrays.equals(keyidOnServer, keyidFromClient)) {
      logger.error(
          "KeyID on Server "
              + Base64.encode2String(keyidOnServer)
              + " not equals KeyID on Client "
              + Base64.encode2String(keyidFromClient));
      throw new RuntimeException(errorMessage);
    }
    byte[] encryptedMessageFromClient = new byte[finishedDataBytes.length - keyidOnServer.length];
    System.arraycopy(
        finishedDataBytes,
        keyidOnServer.length,
        encryptedMessageFromClient,
        0,
        encryptedMessageFromClient.length);
    byte[] decryptedMessage = null;
    try {
      decryptedMessage =
          AESGCM.decrypt(encryptedMessageFromClient, serverSession.getSymKeyClientToServer());
    } catch (Exception e) {
      logger.error(e.getMessage(), e);
      throw new RuntimeException(errorMessage);
    }
    // "VAUClientSigFin"
    // || unkodierter Hashwert aus "VAUClientHelloDataHash"
    // || unkodierter Hashwert aus "VAUServerHelloDataHash"
    byte[] expectedConcatenatedHashesUncoded =
        VAUProtocolHelpers.concat(expectedVauClientHelloDataHash, expectedVauServerHelloDataHash);

    if (!Base64.encode2String(expectedVauClientHelloDataHash)
        .equals(vAUClientSigFin.getVAUClientHelloDataHash())) {
      logger.error(
          "expected vauClientHelloDataHash "
              + Base64.encode2String(expectedVauClientHelloDataHash)
              + " but got "
              + vAUClientSigFin.getVAUClientHelloDataHash());
      throw new RuntimeException(errorMessage);
    }

    if (!Base64.encode2String(expectedVauServerHelloDataHash)
        .equals(vAUClientSigFin.getVAUServerHelloDataHash())) {
      logger.error(
          "expected vauServerHelloDataHash "
              + Base64.encode2String(expectedVauServerHelloDataHash)
              + " but got "
              + vAUClientSigFin.getVAUServerHelloDataHash());
      throw new RuntimeException(errorMessage);
    }

    byte[] expectedMessage =
        VAUProtocolHelpers.concat(
            "VAUClientSigFin".getBytes(StandardCharsets.UTF_8), expectedConcatenatedHashesUncoded);
    if (expectedMessage.length != 79) {
      logger.error("message.length = " + expectedMessage.length + ", expected is 79");
      throw new RuntimeException(errorMessage);
    }
    if (!Arrays.equals(decryptedMessage, expectedMessage)) {
      logger.error(
          "decryptedMessage = "
              + decryptedMessage
              + " not equals expectedMessage = "
              + expectedMessage);
      throw new RuntimeException(errorMessage);
    }
  }

  public static void checkFinishedDataFromServer(
      VAUProtocolSession session, VAUServerFin vAUServerFin) {
    // Der Client MUSS beim Empfang der VAUServerFin-Nachricht prüfen, ob der Wert im
    // "FinishedData"-Feld
    // der nach A_16899 zu erwartenden Wert entspricht.
    // Falls nein, so MUSS der Client den weiteren Protokollablauf abbrechen (vgl. A_16849).

    byte[] vauClientHelloDataHash = session.getClientHelloDataHash();
    byte[] vauServerHelloDataHash = session.getServerHelloDataHash();

    String errorMessage = "VAUServerFin invalid";
    byte[] finishedDataBytes = Base64.decode(vAUServerFin.getFinishedData());
    byte[] keyidOnServer = session.getKeyID();
    byte[] keyidFromServer = new byte[keyidOnServer.length];
    System.arraycopy(finishedDataBytes, 0, keyidFromServer, 0, keyidOnServer.length);
    if (!Arrays.equals(keyidOnServer, keyidFromServer)) {
      logger.error(
          "KeyID on Server "
              + Base64.encode2String(keyidOnServer)
              + " not equals KeyID on Client "
              + Base64.encode2String(keyidFromServer));
      throw new RuntimeException(errorMessage);
    }
    byte[] encryptedMessageFromServer = new byte[finishedDataBytes.length - keyidOnServer.length];
    System.arraycopy(
        finishedDataBytes,
        keyidOnServer.length,
        encryptedMessageFromServer,
        0,
        encryptedMessageFromServer.length);
    byte[] decryptedMessage = null;
    try {
      decryptedMessage =
          AESGCM.decrypt(encryptedMessageFromServer, session.getSymKeyServerToClient());
    } catch (Exception e) {
      logger.error(e.getMessage(), e);
      throw new RuntimeException(errorMessage);
    }
    // "VAUServerFin"
    // || unkodierter Hashwert aus "VAUClientHelloDataHash"
    // || unkodierter Hashwert aus "VAUServerHelloDataHash"
    // Diese Zeichenkette MUSS 12+32+32=76 Bytes lang sein.
    byte[] concatenatedHashesUncoded =
        VAUProtocolHelpers.concat(vauClientHelloDataHash, vauServerHelloDataHash);
    byte[] expectedMessage =
        VAUProtocolHelpers.concat(
            "VAUServerFin".getBytes(StandardCharsets.UTF_8), concatenatedHashesUncoded);
    if (expectedMessage.length != 76) {
      logger.error("message.length = " + expectedMessage.length + ", expected is 76");
      throw new RuntimeException(errorMessage);
    }
    if (!Arrays.equals(decryptedMessage, expectedMessage)) {
      logger.error(
          "decryptedMessage = "
              + decryptedMessage
              + " not equals expectedMessage = "
              + expectedMessage);
      throw new RuntimeException(errorMessage);
    }
  }

  public static String prettyJson(String str) {
    try {
      Object json = mapper.readValue(str, Object.class);
      return mapper.writerWithDefaultPrettyPrinter().writeValueAsString(json);
    } catch (Exception ex) {
      // logger.error(ExceptionUtils.getStackTrace(ex));
      logger.info("couldn't pretty print json");
      return str;
    }
  }

  public static void logJSON(Object o) {
    String str = null;
    if (o instanceof String) {
      str = (String) o;
    } else {
      try {
        str = mapper.writeValueAsString(o);
      } catch (JsonProcessingException ex) {
        logger.error("", ex);
      }
    }
    logger.info(prettyJson(str));
  }

  public static byte[] concat(byte[] a, byte[] b) {
    byte[] c = new byte[a.length + b.length];
    System.arraycopy(a, 0, c, 0, a.length);
    System.arraycopy(b, 0, c, a.length, b.length);
    return c;
  }

  public static void checkClientCertificateHash(
      VAUClientSigFin vAUClientSigFin, VAUProtocolCrypto crypto, VAUProtocolSession session) {
    /*
      A_17072-01 - VAU-Protokoll: Empfang der VAUClientSigFin-Nachricht
      Der Server MUSS beim Empfang der VAUClientSigFin-Nachricht prüfen,
      1. ...
      2. ob der Hashwert des Client-Zertifikats aus dem ”Certificate”-Feld gleich dem Hashwert aus dem
      ClientHelloData->CertificateHash-Feld ist (vgl. Erzeugung des Hashwerts in A_16883-01), und
    */

    logger.debug("VAUProtocolSession session: " + session.toString());
    byte[] hashA = session.getClientHelloDataCertificateHash();
    byte[] hashB = crypto.hash(Base64.decode(vAUClientSigFin.getCertificate()));
    if (!Arrays.equals(hashA, hashB)) {
      try {
        if (hashA == null) {
          logger.error("hashA is null");
        } else {
          logger.error("hashA from ClientHelloDataCertificateHash: " + Base64.encode2String(hashA));
        }
        logger.error("hashB from vAUClientSigFin.getCertificate(): " + Base64.encode2String(hashB));
        logger.error("!Arrays.equals(hashA, hashB)");

      } catch (Exception e) {
        logger.error(e.getMessage(), e);
      }
      throw new RuntimeException("Client Certificate inconsistent");
    }
  }
}
