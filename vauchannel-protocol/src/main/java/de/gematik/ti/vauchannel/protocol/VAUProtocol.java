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

import static de.gematik.ti.vauchannel.protocol.VAUProtocolException.*;
import static de.gematik.ti.vauchannel.protocol.helpers.Base64.decode;
import static de.gematik.ti.vauchannel.protocol.helpers.Base64.encode2String;
import static de.gematik.ti.vauchannel.protocol.helpers.ObjectMapperFactory.objectMapper;
import static de.gematik.ti.vauchannel.protocol.helpers.VAUProtocolHelpers.checkServerSignature;
import static de.gematik.ti.vauchannel.protocol.helpers.VAUProtocolHelpers.logJSON;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import de.gematik.rs.vau.*;
import de.gematik.ti.vauchannel.protocol.helpers.*;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import org.apache.commons.codec.Charsets;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Implementiert das Kommunikationsprotokoll zwischen VAU und ePA-Clients gemäß [gemSpec_Krypt]
 * Kapitel 6.
 */
@java.lang.SuppressWarnings("java:S2259") // statical code analysis can't see it all
public class VAUProtocol {
  static final String KeyID = "KeyID";
  static final String AES256GCMKeyServer2Client = "AES-256-GCM-Key-Server-to-Client";
  static final String AES256GCMKeyClient2Server = "AES-256-GCM-Key-Client-to-Server";
  static Logger logger = LoggerFactory.getLogger(VAUProtocol.class);

  static {
    Security.addProvider(new BouncyCastleProvider());
  }

  private ObjectMapper mapper;
  private VAUProtocolCrypto crypto;
  private VAUProtocolSession session;
  private VAUProtocolSessionPersister persister;

  public VAUProtocol(
      VAUProtocolCrypto crypto, VAUProtocolSession session, VAUProtocolSessionPersister persister) {
    this.mapper = objectMapper();
    this.crypto = crypto;
    this.session = session;
    this.persister = persister;
  }

  public VAUProtocol(VAUProtocolCrypto crypto, VAUProtocolSession session) {
    this.mapper = objectMapper();
    this.crypto = crypto;
    this.session = session;
  }

  public static byte[] getKeyIDFromRawRequest(byte[] rawRequest) {
    EncData d = new EncData(rawRequest);
    return d.keyID;
  }

  /**
   * Implementiert [gemSpec_Krypt] Kapitel 6.3, VAUClientHello-Nachricht, mit Anforderung
   * [A_16883-01] und speichert den Autorisierungstoken authzToken in der VAUClientHello-Nachricht
   * (inklusive der Erweiterung gemäß Anforderung A_15592-01)
   *
   * @param authzToken
   * @return
   */
  public String handshakeStep1_generate_VAUClientHello_Message(byte[] authzToken) {
    // A_16833-01
    String authzTokenStr = null;
    if (authzToken != null) {
      authzTokenStr = Base64.encode2String(authzToken);
    }
    VAUClientHello vAUClientHello = handshakeStep1_generate_VAUClientHello_Object(authzTokenStr);
    String message = null;
    try {
      message = mapper.writeValueAsString(vAUClientHello);
    } catch (JsonProcessingException e) {
      handleNotRecoverableException(e, SYNTAX_ERROR);
    }
    logJSON(message);
    tryToPersist();
    return message;
  }

  private VAUClientHello handshakeStep1_generate_VAUClientHello_Object(
      String authorizationAssertion) {

    session().initialize();

    // Der Client MUSS die Kommunikation mittels einer VAUClientHello-Nachricht initiieren.
    // Dafür erzeugt er zunächst eine VAUCientHelloData-Datenstruktur der Form
    // {
    // "DataType" : "VAUClientHelloData",
    // "CipherConfiguration" : [ "AES-256-GCM-BrainpoolP256r1-SHA-256" ],
    // "PublicKey" : "...Base64-kodierter-ECC-Schlüssel(DER)...",
    // "AuthorizationAssertion" : "Authorizaton Assertion (Base64-kodiert)",
    // "CertificateHash" : "...Base64-kodierter SHA-256 Hashwert des Client-X.509-Zertifikats"
    // }

    // Der Client MUSS im Rahmen der Schlüsselaushandlung ein ECDH-Schlüsselpaar basierend auf der
    // Kurve BrainpoolP256r1 [RFC-5639] erzeugen. Er MUSS im "PublicKey"-Feld den öffentlichen Punkt
    // des
    // ephemeren ECDH-Schlüsselpaares Base64-kodiert gemäß [TR-03111#5.1.1 X9.62 Format] eintragen.
    // Im ”AuthorizationAssertion”-Feld MUSS der Client die Base64-kodierte Authorization-Assertion
    // gemäß A_15592-01 eintragen. Der Client MUSS im ”CertificateHash”-Feld den Base64-kodierten
    // Hashwert
    // seines Client-Zertifikats (AUT- oder AUT_alt-Zertifikat) eintragen (Der Hashwert wird vom
    // kompletten
    // DER-kodierten X.509-Zertifikat inkl. äußerer Zertifikatssignatur erzeugt. Der SHA-256
    // Hashwert
    // (d. h. 256-Bit = 32 Byte) wird anschließend Base64-kodiert. Diese Kodierung wird als Wert bei
    // ”CertificateHash” eingetragen.).

    VAUClientHelloData vAUClientHelloData = new VAUClientHelloData();
    vAUClientHelloData.setAuthorizationAssertion(authorizationAssertion);
    vAUClientHelloData.setDataType(VAUClientHelloData.DataType.VAU_CLIENT_HELLO_DATA);
    vAUClientHelloData.setCipherConfiguration(VAUProtocolHelpers.getCipherConfiguration());

    try {
      byte[] certBytes = crypto.getEECertificate().getEncoded();
      String certHash = Base64.encode2String(crypto.hash(certBytes));
      vAUClientHelloData.setCertificateHash(certHash);
    } catch (Exception e) {
      handleNotRecoverableException(e, INTERNAL_SERVER_ERROR);
    }
    session().setEphemeralKeyPair(crypto.generateECCKeyPair());
    vAUClientHelloData.setPublicKey(
        Base64.encode2String(session().getEphemeralKeyPair().getPublic().getEncoded()));
    String vAUClientHelloDataStr = null;
    try {
      vAUClientHelloDataStr = mapper.writeValueAsString(vAUClientHelloData);
    } catch (JsonProcessingException e) {
      handleNotRecoverableException(e, SYNTAX_ERROR);
    }
    logJSON(vAUClientHelloDataStr);
    byte[] data = Base64.encode(vAUClientHelloDataStr);
    session().setClientHelloDataHash(crypto.hash(data));
    // In das Datenfeld "Data" in der folgenden VAUClientHello-Nachricht MUSS er die Base64-kodierte
    // VAUClientHelloData-Daten eintragen.
    VAUClientHello vAUClientHello = new VAUClientHello();
    vAUClientHello.setMessageType(VAUClientHello.MessageType.VAU_CLIENT_HELLO);
    vAUClientHello.setData(new String(data, StandardCharsets.UTF_8));

    return vAUClientHello;
  }

  /**
   * Implementiert [gemSpec_Krypt] Kapitel 6.4, VAUServerHello-Nachricht, mit Anforderungen
   * [A_16898], [A_16901-01]
   *
   * @param vAUClientHelloStr
   * @return
   */
  public String handshakeStep2_generate_VAUServerHello_Message(String vAUClientHelloStr) {

    session().initialize();

    try {
      logJSON(vAUClientHelloStr);
      VAUClientHello vAUClientHello = mapper.readValue(vAUClientHelloStr, VAUClientHello.class);

      VAUServerHello vAUServerHello = handshakeStep2_generate_VAUServerHello_Object(vAUClientHello);
      String vAUServerHelloStr = mapper.writeValueAsString(vAUServerHello);
      logJSON(vAUServerHelloStr);
      tryToPersist();
      return vAUServerHelloStr;
    } catch (Exception e) {
      logger.error(e.getMessage(), e);
      if (CONTEXT_MANAGER_ACCESS_DENIED.equals(e.getMessage())) {
        return CONTEXT_MANAGER_ACCESS_DENIED;
      }
      return generateVAUServerErrorMessage(e.getMessage());
    }
  }

  private VAUServerHello handshakeStep2_generate_VAUServerHello_Object(
      VAUClientHello vAUClientHello) {
    // A_16898 - VAU-Protokoll: Erzeugung des Hashwert vom Data-Feld aus der
    // VAUClientHello-Nachricht
    // Der Server MUSS beim Empfang der VAUClientHello-Nachricht einen SHA-256-Hashwert der Daten im
    // Data-Feld
    // (zunächst keine Base64-Dekodierung durchführen) erzeugen.
    String vAUClientHelloDataStr = vAUClientHello.getData();
    logJSON(vAUClientHelloDataStr);
    byte[] vAUClientHelloDataHash =
        crypto.hash(vAUClientHelloDataStr.getBytes(StandardCharsets.UTF_8));
    // A_16901-01 - VAU-Protokoll: Aufbau der VAUServerHello-Nachricht
    // Der Server MUSS auf die VAUClientHello-Nachricht mit einer VAUServerHello-Nachricht,
    // folgender Form,
    // antworten
    // {
    // "MessageType" : "VAUServerHello",
    // "Data" : "...Base64-kodierte-Daten...",
    // "Signature" : "...Base64-kodierte-ECDSA-Signatur...",
    // "Certificate" : "...Base64-kodiertes-Signaturzertifikat...",
    // "OCSPResponse" : "...Base64-kodierte-OCSP-Response-für-dieses-Zertifikat..."
    // }
    VAUServerHello vAUServerHello = new VAUServerHello();
    vAUServerHello.setMessageType(VAUServerHello.MessageType.VAU_SERVER_HELLO);
    // Die ECDSA-Signatur MUSS nach [TR-03111#5.2.2. X9.62 Format] (inkl. OID "ecdsa-with-Sha256")
    // kodiert sein.
    // In den Daten von "Data" MUSS der Server in die Base64-kodierte
    // VAUServerHelloData-Datenstruktur der
    // folgenden Form eintragen. Der Server MUSS im "CertificateHash"-Feld den Base64-kodierten
    // SHA-256 Hashwert
    // des Server-X.509-Zertifikats eintragen. (Der Hashwert wird vom kompletten DER-kodierten
    // X.509-Zertifikat
    // inkl. äußerer Zertifikatssignatur erzeugt. Der SHA-256 Hashwert (d. h. 256-Bit = 32 Byte)
    // wird anschließend Base64-kodiert. Diese Kodierung wird als Wert bei ”CertificateHash”
    // eingetragen.)
    // {
    // "DataType" : "VAUServerHelloData",
    // "CipherConfiguration" : [ "AES-256-GCM-BrainpoolP256r1-SHA-256" ],
    // "VAUClientHelloDataHash" :
    // "...SHA-256-Hashwert-des-erhaltenen-Data-Felds-in-VAUClientHello...",
    // "PublicKey" : "...Base64-kodierter-ECC-Schlüssel(DER)..."
    // "CertificateHash" : "...Base64-kodierter SHA-256 Hashwert des Server-x.509-Zertifikats
    // }
    VAUServerHelloData vAUServerHelloData = new VAUServerHelloData();
    vAUServerHelloData.setDataType(VAUServerHelloData.DataType.VAU_SERVER_HELLO_DATA);
    vAUServerHelloData.setCipherConfiguration(VAUProtocolHelpers.getCipherConfiguration_());
    // Der Server MUSS im "PublicKey"-Feld den öffentlichen Punkt seines ephemeren
    // ECDH-Schlüsselpaares
    // Base64-kodiert gemäß [TR-03111#5.1.1 X9.62 Format] eintragen.
    session().setEphemeralKeyPair(crypto.generateECCKeyPair());
    vAUServerHelloData.setPublicKey(
        Base64.encode2String(session().getEphemeralKeyPair().getPublic().getEncoded()));
    // Der Server MUSS im Feld "VAUClientHelloDataHash" den Base64-kodierten SHA-256-Hashwert der
    // empfangenen
    // VAUClientHelloData (ohne Base64-Dekodierung) eintragen (vgl. A_16898).
    vAUServerHelloData.setVAUClientHelloDataHash(encode2String(vAUClientHelloDataHash));

    // A_16901-01
    try {
      byte[] certBytes = crypto.getEECertificate().getEncoded();
      String certHash = Base64.encode2String(crypto.hash(certBytes));
      vAUServerHelloData.setCertificateHash(certHash);
    } catch (Exception e) {
      handleNotRecoverableException(e, INTERNAL_SERVER_ERROR);
    }

    // VAUServerHelloData in VAUServerHello setzen
    String vAUServerHelloDataStr = null;
    try {
      vAUServerHelloDataStr = mapper.writeValueAsString(vAUServerHelloData);
    } catch (JsonProcessingException e) {
      handleNotRecoverableException(e, SYNTAX_ERROR);
    }
    logJSON(vAUServerHelloData);
    vAUServerHello.setData(
        Base64.encode2String(vAUServerHelloDataStr.getBytes(StandardCharsets.UTF_8)));
    // Der Server MUSS die in der Datenstruktur (VAUServerHello) angegebene Signatur erzeugen
    // (über den Base64-kodieren Wert im "Data"-Feld).
    try {
      vAUServerHello.setSignature(
          Base64.encode2String(
              crypto.signECDSA(vAUServerHello.getData().getBytes(StandardCharsets.UTF_8))));
    } catch (Exception e) {
      handleNotRecoverableException(e, INTERNAL_SERVER_ERROR);
    }
    // Im "Certificates"-Feld MUSS er die für eine Signaturprüfung notwendigen EE-Zertifikate
    // eintragen
    try {
      vAUServerHello.setCertificate(Base64.encode2String(crypto.getEECertificate().getEncoded()));
    } catch (CertificateEncodingException e) {
      handleNotRecoverableException(e, INTERNAL_SERVER_ERROR);
    }
    // und im "OCSPResponses"-Feld die OCSP-Responses, die nicht älter als 24 Stunden sein dürfen,
    // für diese EE-Zertifikate.
    if (crypto.canProvideOcspResponse()) {
      try {
        vAUServerHello.setOCSPResponse(Base64.encode2String(crypto.getOcspResponse().getEncoded()));
      } catch (IOException e) {
        handleNotRecoverableException(e, INTERNAL_SERVER_ERROR);
      }
    }
    // key derivation
    VAUClientHelloData vAUClientHelloData = null;
    try {
      vAUClientHelloData =
          mapper.readValue(Base64.decode(vAUClientHelloDataStr), VAUClientHelloData.class);
    } catch (IOException e) {
      handleNotRecoverableException(e, SYNTAX_ERROR);
    }

    // A_16883-01
    String authorizationAssertionStr = vAUClientHelloData.getAuthorizationAssertion();
    if (authorizationAssertionStr != null) {
      session.setAuthzToken(authorizationAssertionStr.getBytes(StandardCharsets.UTF_8));
    }
    crypto.validateAuthorizationAssertion(session, authorizationAssertionStr);

    // A_12072-01, 2., remember ClientHelloData.CertificateHash
    session.setClientHelloDataCertificateHash(
        Base64.decode(vAUClientHelloData.getCertificateHash()));
    session.setClientHelloDataHash(vAUClientHelloDataHash);

    PublicKey ephemeralPublicKeyClient =
        crypto.eccPublicKeyFromBytes(Base64.decode(vAUClientHelloData.getPublicKey()));
    keyDerivation(ephemeralPublicKeyClient);
    // remember hash VAUServerHelloData
    byte[] hash = crypto.hash(vAUServerHello.getData().getBytes(StandardCharsets.UTF_8));
    session().setServerHelloDataHash(hash);

    return vAUServerHello;
  }

  /**
   * Implementiert [gemSpec_Krypt] Kapitel 6.5, Schlüsselableitung, mit Anforderungen [A_16852-01],
   * [A_16943-01]
   *
   * @param ephemeralPublicKeyCounterpart
   */
  private void keyDerivation(PublicKey ephemeralPublicKeyCounterpart) {
    // Der Client und auch der Server MÜSSEN jeweils für sich prüfen, ob der empfangene ephemere
    // öffentliche elliptische Kurvenpunkt der Gegenseite auch auf der von ihnen
    // verwendeten Kurve (BrainpoolP256r1) liegt.
    BCECPublicKey ephemeralPublicKeyClientBC = (BCECPublicKey) ephemeralPublicKeyCounterpart;
    ECNamedCurveSpec spec = (ECNamedCurveSpec) ephemeralPublicKeyClientBC.getParams();
    if (!"brainpoolP256r1".equals(spec.getName())) {
      // Falls nein, MÜSSEN sie jeweils den Protokollablauf abbrechen. Falls der Server derjenige
      // ist,
      // der in diesem Fall abbricht, MUSS der zuvor an den Client eine VAUServerError-Nachricht
      // mit der Fehlermeldung "invalid curve (ECDH)" senden.
      handleNotRecoverableException(INVALID_CURVE_ECDH); // [A_16852-01]
    }
    // Falls ja, MÜSSEN beide einen ECDH nach [NIST-800-56-A] durchführen. Das dabei erzeugte
    // gemeinsame Geheimnis
    // ist folgend Grundlage von zwei Schlüsselableitungen.
    try {
      session()
          .setShare(
              crypto.ECKA(
                  session().getEphemeralKeyPair().getPrivate(), ephemeralPublicKeyCounterpart));
    } catch (Exception e) {
      handleNotRecoverableException(e, INTERNAL_SERVER_ERROR);
    }
    logger.info("shared secret: " + Hex.encodeHexString(session().getShare()));
    //  Für die Schlüsselableitung MÜSSEN Client und Server die HKDF nach [RFC-5869]
    //  auf Basis von SHA-256 verwenden. Das ”Input Keying Material” (IKM) [RFC-5869]
    //  ist das in A_16852-01 erzeugte gemeinsame ECDH-Geheimnis zwischen Server und Client.
    //  Die erste Schlüsselableitung hat den Ableitungsvektor ”KeyID” (”info” Paramet aus [RFC-5869]
    // ist
    //  dann also ”KeyID”) und erzeugt einen 256 Bit langen Schlüsselidentifier.
    session().setKeyID(crypto.HKDF(session().getShare(), KeyID, 256));
    logger.info("keyID: " + Hex.encodeHexString(session().getKeyID()));
    // Die zweite Schlüsselableitung mit dem Ableitungsvektor ”AES-256-GCM-Key-Client-to-Server”
    // erzeugt den
    // 256-Bit AES-Schlüssel für die Verwendung innerhalb vo AES-256-GCM für Nachrichten, die der
    // Client
    // für den Server verschlüsselt.
    session()
        .setSymKeyClientToServer(crypto.HKDF(session().getShare(), AES256GCMKeyClient2Server, 256));
    logger.info(
        "AES-256-GCM-Key-Client-to-Server: "
            + Hex.encodeHexString(session().getSymKeyClientToServer()));
    // Die dritte Schlüsselableitung mit dem Ableitungsvektor ”AES-256-GCM-Key-Server-to-Client”
    // erzeugt
    // den 256-Bit AES-Schlüssel für die Verwendung inner von AES-256-GCM für Nachrichten, die der
    // Server
    // für den Client verschlüsselt.
    session()
        .setSymKeyServerToClient(crypto.HKDF(session().getShare(), AES256GCMKeyServer2Client, 256));
    logger.info(
        "AES-256-GCM-Key-Server-to-Client: "
            + Hex.encodeHexString(session().getSymKeyServerToClient()));
  }

  /**
   * Implementiert [gemSpec_Krypt] Kapitel 6.6, VAUClientSigFin-Nachricht, mit Anforderungen
   * [A_17070-01], [A_16941-01], [A_16903]
   *
   * @param vAUServerHelloStr
   * @return
   */
  public String handshakeStep3_generate_VAUClientSigFin_Message(String vAUServerHelloStr) {
    logJSON(vAUServerHelloStr);
    VAUServerHello vAUServerHello = null;
    try {
      vAUServerHello = mapper.readValue(vAUServerHelloStr, VAUServerHello.class);
    } catch (Exception e) {
      try {
        VAUServerError vauServerError = mapper.readValue(vAUServerHelloStr, VAUServerError.class);
      } catch (IOException ex) {
        handleNotRecoverableException(e, SYNTAX_ERROR);
      }
      String serverErrorStr = validateAndUnpackServerError(vAUServerHelloStr);
      throw new VAUProtocolException(serverErrorStr);
    }
    VAUClientSigFin vAUClientSigFin =
        handshakeStep3_generate_VAUClientSigFin_Object(vAUServerHello);
    String vAUClientSigFinStr = null;
    try {
      vAUClientSigFinStr = mapper.writeValueAsString(vAUClientSigFin);
    } catch (JsonProcessingException e) {
      handleNotRecoverableException(e, SYNTAX_ERROR);
    }
    logJSON(vAUClientSigFinStr);
    tryToPersist();

    return vAUClientSigFinStr;
  }

  private VAUClientSigFin handshakeStep3_generate_VAUClientSigFin_Object(
      VAUServerHello vAUServerHello) {

    // A_16941-01 - VAU-Protokoll: Client, Prüfung der Signatur der VAUServerHelloData
    // Der Client MUSS die Signatur der Daten von "Data" prüfen (bitgenau den Datenwert von "Data"
    // nehmen, ohne Base64-Dekodierung).
    // HIER NICHT AUSGEFÜHRT: Der Client MUSS dafür den Signaturschlüssel des Servers auf
    // Authentizität und Integrität prüfen.
    // HIER NICHT AUSGEFÜHRT: (Hinweis: in einem Client wird die TSL der TI als Prüfgrundlage für
    // die Prüfung von TI-Zertifikaten verwendet.)
    // Falls die Signaturprüfung kein positives Ergebnis erbringt, so MUSS der Client den
    // Protokollablauf abbrechen (vgl. A_16849).
    String vAUServerHelloDataStr = new String(Base64.decode(vAUServerHello.getData()));
    logJSON(vAUServerHelloDataStr);
    checkServerSignature(vAUServerHello, crypto);

    // A_16903 - VAU-Protokoll: Client, Prüfung des VAUClientHelloDataHash-Werts (aus
    // VAUServerHelloData)
    // Der Client MUSS beim Empfang der VAUServerHello-Nachricht den Hashwert
    // "VAUClientHelloDataHash"
    // (vgl. A_16901) mit dem vom ihm (Client) vor dem Versand der VAUClientHello-Nachricht (vgl.
    // A_16883)
    // errechneten Wert vergleichen. Sind die beiden Werte verschieden, so MUSS der Client den
    // Protokollablauf abbrechen.
    VAUServerHelloData vAUServerHelloData = null;
    try {
      vAUServerHelloData = mapper.readValue(vAUServerHelloDataStr, VAUServerHelloData.class);
    } catch (IOException e) {
      handleNotRecoverableException(e, SYNTAX_ERROR);
    }
    if (!Arrays.equals(
        Base64.decode(vAUServerHelloData.getVAUClientHelloDataHash()),
        this.session.getClientHelloDataHash())) {
      handleNotRecoverableException(UNEXPECTED_VAU_CLIENT_HELLLO_DATA_HASH_ERROR);
    }

    // A_16941-01
    String hashStrA = vAUServerHelloData.getCertificateHash();
    String hashStrB =
        Base64.encode2String(crypto.hash(Base64.decode(vAUServerHello.getCertificate())));
    if (!hashStrA.equals(hashStrB)) {
      handleNotRecoverableException(UNEXPECTED_CERTIFICATE_HASH_ERROR);
    }

    // Der Client MUSS auf eine VAUServerHello-Nachricht mit einer wie folgt definierten
    // VAUClientSigFin-Nachricht antworten. Die VAUClientSigFin-Nachricht hat folgenden Aufbau:
    // {
    // "MessageType" : "VAUClientSigFin",
    // "VAUClientHelloDataHash" : "...SHA-256-Hashwert-der-Base64-kodierten-VAUClientHelloData...",
    // "VAUServerHelloDataHash" :
    // "...SHA-256-Hashwert-der-erhaltenen-Base64-kodierten-VAUServerHelloData...",
    // "Signature" : "...Base64-kodierte-Signatur...",
    // "Certificate" : "...Base64-kodiertes-Signaturzertifikat...",
    // "OCSPResponse" : "...Base64-kodierte-OCSP-Response-für-dieses-Zertifikat...",
    // "FinishedData" : "...Base64-kodierte-verschlüsselte-Finished-Daten ..."
    // }
    VAUClientSigFin vAUClientSigFin = new VAUClientSigFin();
    vAUClientSigFin.setOCSPResponse(""); // according to A_17070-01
    vAUClientSigFin.setMessageType(VAUClientSigFin.MessageType.VAU_CLIENT_SIG_FIN);
    // Im "VAUClientHelloDataHash"-Feld MUSS der Client den Base64-kodieren Hashwert seiner
    // Base64-kodierten VAUClientHelloData eintragen.
    vAUClientSigFin.setVAUClientHelloDataHash(
        Base64.encode2String(session().getClientHelloDataHash()));
    // Im "VAUServerHelloDataHash"-Feld MUSS der Client den Base64-kodieren Hashwert der empfangenen
    // Base64-kodierten VAUServerHelloData eintragen.
    byte[] hash = crypto.hash(vAUServerHello.getData().getBytes(StandardCharsets.UTF_8));
    session().setServerHelloDataHash(hash);
    vAUClientSigFin.setVAUServerHelloDataHash(Base64.encode2String(hash));
    // Die folgende Signatur MUSS der Client über die beiden konkatenierten Base64-kodierten
    // Zeichenketten
    // (Inhalt vom "VAUClientHelloDataHash"-Feld || Inhalt vom "VAUClientServerDataHash"-Feld)
    // bilden.
    // Eine ECDSA-Signatur im "Signature"-Feld MUSS nach [TR-03111#5.2.2. X9.62 Format] (inkl. OID
    // "ecdsa-with-Sha256")
    // kodiert sein. Ein RSASSA-PSS-Signatur MUSS nach [PKCS#1] kodiert werden.
    byte[] concatenatedHashes =
        VAUProtocolHelpers.concat(
            vAUClientSigFin.getVAUClientHelloDataHash().getBytes(StandardCharsets.UTF_8),
            vAUClientSigFin.getVAUServerHelloDataHash().getBytes(StandardCharsets.UTF_8));
    if (crypto.isECCIdentity()) {
      try {
        vAUClientSigFin.setSignature(Base64.encode2String(crypto.signECDSA(concatenatedHashes)));
      } catch (Exception e) {
        handleNotRecoverableException(e, INTERNAL_SERVER_ERROR);
      }
    } else {
      try {
        vAUClientSigFin.setSignature(
            Base64.encode2String(crypto.signRSASSA_PSS(concatenatedHashes)));
      } catch (Exception e) {
        handleNotRecoverableException(e, INTERNAL_SERVER_ERROR);
      }
    }
    // Der Client MUSS im "Certificates"-Feld die für die Prüfung der Signatur notwendige
    // X.509-EE-Zertifikat im Base64-kodiert eintragen.
    try {
      vAUClientSigFin.setCertificate(Base64.encode2String(crypto.getEECertificate().getEncoded()));
    } catch (CertificateEncodingException e) {
      handleNotRecoverableException(e, INTERNAL_SERVER_ERROR);
    }
    // Er SOLL für dieses Zertifikat im "OCSPResponses"-Feld die OCSP-Responses, die nicht älter als
    // 24 Stunden sein dürfen, eintragen.
    // HIER NICHT AUSGEFÜHRT

    // key derivation
    PublicKey ephemeralPublicKeyFromServer =
        crypto.eccPublicKeyFromBytes(Base64.decode(vAUServerHelloData.getPublicKey()));
    keyDerivation(ephemeralPublicKeyFromServer);

    // Der Client MUSS für die Berechnung des "FinishedData"-Feldes zunächst folgende Zeichenkette
    // bilden
    // "VAUClientSigFin"
    // || unkodierter Hashwert aus "VAUClientHelloDataHash"
    // || unkodierter Hashwert aus "VAUServerHelloDataHash"
    // Diese Zeichenkette MUSS 15+32+32=79 Bytes lang sein.
    byte[] concatenatedHashesUncoded =
        VAUProtocolHelpers.concat(
            Base64.decode(vAUClientSigFin.getVAUClientHelloDataHash()),
            Base64.decode(vAUClientSigFin.getVAUServerHelloDataHash()));
    byte[] stringBytes =
        VAUProtocolHelpers.concat(
            "VAUClientSigFin".getBytes(StandardCharsets.UTF_8), concatenatedHashesUncoded);
    // Der Client MUSS diese Zeichenkette mittels AES-GCM (vgl. A_16943-01) verschlüsseln
    byte[] encryptedBytes = new byte[0];
    try {
      encryptedBytes = AESGCM.encrypt(stringBytes, session().getSymKeyClientToServer());
    } catch (Exception e) {
      handleNotRecoverableException(e, INTERNAL_SERVER_ERROR);
    }
    // und dabei
    // folgende Zeichenkette bilden
    // 256-Bit KeyID
    // || 96-Bit Nonce (IV) mit Ciphertext und 128 Bit Authentication-Tag
    // Diese Zeichenkette MUSS er Base64-kodieren und das Ergebnis als Wert des "FinishedData"-Feld
    // eintragen.
    vAUClientSigFin.setFinishedData(
        Base64.encode2String(VAUProtocolHelpers.concat(session().getKeyID(), encryptedBytes)));

    return vAUClientSigFin;
  }

  /**
   * Implementiert [gemSpec_Krypt] Kapitel 6.7, VAUServerFin-Nachricht, mit Anforderungen
   * [A_17072-01], [A_16899], [A_17073]
   *
   * @param vAUClientSigFinStr
   * @return
   */
  public String handshakeStep4_generate_VAUServerFin_Message(String vAUClientSigFinStr) {
    try {
      logJSON(vAUClientSigFinStr);
      VAUClientSigFin vAUClientSigFin = mapper.readValue(vAUClientSigFinStr, VAUClientSigFin.class);
      vAUClientSigFin.setMessageType(VAUClientSigFin.MessageType.VAU_CLIENT_SIG_FIN);
      VAUServerFin vAUServerFin = handshakeStep4_generate_VAUServerFin_Object(vAUClientSigFin);
      String vAUServerFinStr = mapper.writeValueAsString(vAUServerFin);
      logJSON(vAUServerFinStr);
      // aus Sicht des Servers kann der VAU-Kanal für den Transport verwendet werden
      session.setState(VAUProtocolSessionState.open);
      tryToPersist();
      return vAUServerFinStr;
    } catch (Exception e) {
      logger.error(e.getMessage(), e);
      return generateVAUServerErrorMessage(e.getMessage());
    }
  }

  private VAUServerFin handshakeStep4_generate_VAUServerFin_Object(
      VAUClientSigFin vAUClientSigFin) {
    // A_17072-01 - VAU-Protokoll: Empfang der VAUClientSigFin-Nachricht
    // Der Server MUSS beim Empfang der VAUClientSigFin-Nachricht prüfen,
    // 1. ob die darin enthaltene Signatur gültig ist, und
    VAUProtocolHelpers.checkClientSignature(vAUClientSigFin, crypto);
    // 2. ob der Hashwert des Client-Zertifikats aus dem ”Certificate”-Feld gleich dem
    // Hashwert aus dem ClientHelloData->CertificateHash-Feld ist (vgl. Erzeugung des Hashwerts in
    // A_16883),
    VAUProtocolHelpers.checkClientCertificateHash(vAUClientSigFin, crypto, session);

    // 3. ob der Wert im "FinishedData"-Feld der nach A_17070-01 zu erwartenden Wert entspricht.
    VAUProtocolHelpers.checkFinishedDataFromClient(
        session(),
        vAUClientSigFin,
        this.session.getClientHelloDataHash(),
        this.session.getServerHelloDataHash());

    // Der Server MUSS eine wie folgt aufgebaute VAUServerFin-Nachricht erzeugen.
    // {
    // "MessageType" : "VAUServerFin",
    // "FinishedData" : "...Base64-kodierte-verschlüsselte-Finished-Daten..."
    // }
    VAUServerFin vAUServerFin = new VAUServerFin();
    vAUServerFin.setMessageType(VAUServerFin.MessageType.VAU_SERVER_FIN);

    // Der Server MUSS für die Berechnung des "FinishedData"-Feldes zunächst folgende Zeichenkette
    // bilden
    // "VAUServerFin"
    // || unkodierter Hashwert aus "VAUClientHelloDataHash"
    // || unkodierter Hashwert aus "VAUServerHelloDataHash"
    // Diese Zeichenkette MUSS 12+32+32=76 Bytes lang sein.
    byte[] concatenatedHashes =
        VAUProtocolHelpers.concat(
            Base64.decode(vAUClientSigFin.getVAUClientHelloDataHash()),
            session().getServerHelloDataHash());
    concatenatedHashes =
        VAUProtocolHelpers.concat(
            "VAUServerFin".getBytes(StandardCharsets.UTF_8), concatenatedHashes);
    try {
      // Der Server MUSS diese Zeichenkette mittels AES-GCM (vgl. A_16943-01) verschlüsseln
      byte[] encryptedString =
          AESGCM.encrypt(concatenatedHashes, session().getSymKeyServerToClient());
      // und dabei folgende Zeichenkette bilden
      // 256-Bit KeyID || 96-Bit Nonce (IV) mit Ciphertext und 128 Bit Authentication-Tag
      byte[] stringBytes = VAUProtocolHelpers.concat(session().getKeyID(), encryptedString);
      // Diese Zeichenkette MUSS er Base64-kodieren und das Ergebnis als Wert des
      // "FinishedData"-Feld eintragen.
      vAUServerFin.setFinishedData(Base64.encode2String(stringBytes));
    } catch (Exception ex) {
      handleNotRecoverableException(ex, INTERNAL_SERVER_ERROR);
    }
    return vAUServerFin;
  }

  /**
   * Implementiert [gemSpec_Krypt] Kapitel 6.7, VAUServerFin-Nachricht, mit Anforderung [A_17084]
   *
   * @param vAUServerFinStr
   */
  public void handshakeStep5_validate_VAUServerFin_Message(String vAUServerFinStr) {
    // A_17084 - VAU-Protokoll: Empfang der VAUServerFin-Nachricht
    // Der Client MUSS beim Empfang der VAUServerFin-Nachricht prüfen, ob der Wert im
    // "FinishedData"-Feld
    // der nach A_16899 zu erwartenden Wert entspricht.
    // Falls nein, so MUSS der Client den weiteren Protokollablauf abbrechen (vgl. A_16849).
    logJSON(vAUServerFinStr);
    VAUServerFin vAUServerFin = null;
    try {
      vAUServerFin = mapper.readValue(vAUServerFinStr, VAUServerFin.class);
    } catch (Exception e) {
      try {
        VAUServerError vauServerError = mapper.readValue(vAUServerFinStr, VAUServerError.class);
      } catch (IOException ex) {
        handleNotRecoverableException(ex, SYNTAX_ERROR);
      }
      String serverErrorStr = validateAndUnpackServerError(vAUServerFinStr);
      throw new VAUProtocolException(serverErrorStr);
    }
    VAUProtocolHelpers.checkFinishedDataFromServer(session(), vAUServerFin);
    // aus Sicht des Clients kann der VAU-Kanal für den Transport verwendet werden
    session().setState(VAUProtocolSessionState.open);
    tryToPersist();
  }

  /**
   * Implementiert [gemSpec_Krypt] Kapitel 6.9, VAU-Protokoll: VAUServerError-Nachrichten, mit
   * Anforderungen [A_16851]
   *
   * @param errorMessage
   * @return
   */
  public String generateVAUServerErrorMessage(String errorMessage) {
    try {
      if (errorMessage == null) {
        errorMessage = INTERNAL_SERVER_ERROR;
      }
      // Für die eigentliche Fehlerübermittlung MUSS folgende Datenstruktur erzeugt:
      // {
      // "DataType" : "VAUServerErrorData",
      // "Data" : "...Fehlermeldung...",
      // "Time" : "...aktuelle-Zeit-in-der-VAU..."
      // }
      VAUServerErrorData data = new VAUServerErrorData();
      data.setDataType(VAUServerErrorData.DataType.VAU_SERVER_ERROR_DATA);
      // Die Zeit im "Time"-Feld MUSS im Format nach ISO-8601 kodiert werden
      // (Beispiel: "2018-11-22-T10:00:00.123456").
      data.setTime(crypto.now());
      data.setData(errorMessage);
      // Diese Datenstruktur MUSS der Server Base64-kodieren und in der folgenden Nachricht
      // im Datenfeld "Data" einbetten.
      // {
      // "MessageType" : "VAUServerError",
      // "Data" : "...Base64-kodierte-VAUServerErrorData..",
      // "Signature" : "...Base64-kodierte-ECDSA-Signatur...",
      // "Certificate" : "...Base64-kodiertes-Signaturzertifikat...",
      // "OCSPResponse" : "...Base64-kodierte-OCSP-Response-für-dieses-Zertifikat..."
      // }
      VAUServerError error = new VAUServerError();
      error.setMessageType(VAUServerError.MessageType.VAU_SERVER_ERROR);
      String dataStr = mapper.writeValueAsString(data);
      logJSON(dataStr);
      String data64Str = Base64.encode2String(dataStr.getBytes(Charsets.UTF_8));
      error.setData(data64Str);
      // Die ECDSA-Signatur im "Signature"-Feld MUSS nach [TR-03111#5.2.2. X9.62 Format]
      // (inkl. OID "ecdsa-with-Sha256") kodiert sein.
      error.setSignature(encode2String(crypto.signECDSA(data64Str.getBytes(Charsets.UTF_8))));
      // Im "Certificate"-Feld MUSS der Server, das verwendete Signaturzertifikat aufführen,
      error.setCertificate(encode2String(crypto.getEECertificate().getEncoded()));
      // und im "OCSPResponse"-Feld eine OCSP-Response für diese Zertifikat,
      // welche nicht älter als 24 Stunden ist.
      if (crypto.canProvideOcspResponse()) {
        error.setOCSPResponse(encode2String(crypto.getOcspResponse().getEncoded()));
      }
      logJSON(error);
      return mapper.writeValueAsString(error);
    } catch (Exception e) {
      logger.error(e.getMessage(), e);
      return errorMessage; // should not happen
    }
  }

  public String validateAndUnpackServerError(String serverErrorStr) {
    try {
      VAUServerError vAUServerError = mapper.readValue(serverErrorStr, VAUServerError.class);
      byte[] certBytes = Base64.decode(vAUServerError.getCertificate());
      CertificateFactory certFactory =
          CertificateFactory.getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME);
      InputStream in = new ByteArrayInputStream(certBytes);
      X509Certificate cert = (X509Certificate) certFactory.generateCertificate(in);
      PublicKey publicKey = cert.getPublicKey();
      boolean ok =
          this.crypto.verify(
              vAUServerError.getData().getBytes(StandardCharsets.UTF_8),
              Base64.decode(vAUServerError.getSignature()),
              publicKey);
      if (!ok) throw new VAUProtocolException(SERVER_ERROR_SIGNATURE_NOT_VALID);
      VAUServerErrorData vauServerErrorData =
          mapper.readValue(decode(vAUServerError.getData()), VAUServerErrorData.class);
      return vauServerErrorData.getData();
    } catch (Exception e) {
      logger.error(e.getMessage(), e);
      return EXCEPTION_PARSING_SERVER_ERROR;
    }
  }

  public VAUProtocolSession session() {
    return session;
  }

  public VAUProtocolCrypto crypto() {
    return crypto;
  }

  /**
   * Implementiert die Datenverschlüsselung gemäß [gemSpec_Krypt] Kapitel 6.8, Nutzerdatentransport
   *
   * @param transportedData
   * @return
   */
  public byte[] encrypt(TransportedData transportedData) {

    // zum Testen
    if (session.isForceErrorInEncryptIfCountIs6() && session.getCounter() == 5) {
      handleNotRecoverableException(ERROR_FORCED_BY_CONFIGURATION);
    }
    // mit C_7029
    // Wie bei der Schlüsselaushandlung MUSS der Client mittels HTTP-POST-Request die nun
    // verschlüsselte
    // Kommunikation initiieren. Sei "Plaintext" die zu übermittelnde Nachricht. Der Client MUSS
    // einen
    // unsigned 64-Bit-Nachrichtenzähler führen, den er bei jeder abgeschick-ten Nachricht um zwei
    // erhöhen MUSS.
    // Er bildet die Datenstruktur "P1" mit
    // P1=Version (ein Byte mit dem Wert 0x01)
    // || Nachrichtenzähler (unsigned 64-Bit im Big-Endian-Format)
    // || Anzahl der Bytes der folgenden optionalen zusätzlichen HTTP-Header-Informationen (unsigned
    // 32-Bit im Big-Endian-Format)
    // || optionale HTTP-Header-Informationen
    // || Plaintext wobei „Plaintext“ die zu übertragende Nutzlast (bspw. SOAP-Request) bezeichne.
    // Wenn die Anzahl der Bytes der folgenden optionalen zusätzlichen HTTP-Header-Informationen
    // mit 0 (also 0x00000000) angegeben wird, so gibt es keine folgenden optiona-len zusätzlichen
    // HTTP-Header-Informationen, d. h. es folgen direkt die Plaintext-Bytes.
    // Verständnishinweis: bez. der optionalen zusätzlichen HTTP-Header-Information vgl.
    // [gemSpec_Krypt#6.11 VAU-Kanal und MTOM/XOP].
    // Der Nachrichtenzähler
    if (session.isClient()) {
      if (session.getCounter() == 0) {
        session.setCounter(1);
      } else {
        session.setCounter(session.getCounter() + 2);
      }
    }
    // Die vom Client nun an den Server zu übermittelnde Datenstruktur MUSS folgende Form besitzen.
    // 256-Bit KeyID || 96-Bit Nonce (IV) mit Ciphertext und 128 Bit
    Data data = new Data(session.getKeyID(), session.getCounter(), transportedData);
    byte[] encData = null;
    try {
      logger.debug("### VAUProtocol.encrypt ###");
      encData =
          crypto.encrypt_AESGCM(
              data.getEncoded(),
              session.isClient()
                  ? session.getSymKeyClientToServer()
                  : session.getSymKeyServerToClient(),
              session.getCounter());
    } catch (Exception e) {
      handleNotRecoverableException(e, ENCRYPTION_NOT_SUCCESSFUL);
    }
    EncData dataWrapper = new EncData(session.getKeyID(), encData);
    encData = dataWrapper.getEncoded();
    tryToPersist();
    return encData;
  }

  /**
   * Implementiert die Datenentschlüsselung gemäß [gemSpec_Krypt] Kapitel 6.8, Nutzerdatentransport
   *
   * @param in
   * @return
   */
  public TransportedData decrypt(byte[] in) {
    if (session != null && session.isForceErrorInDecryptIfCountIs5() && session.getCounter() == 4) {
      handleNotRecoverableException(ERROR_FORCED_BY_CONFIGURATION);
    }
    EncData d = new EncData(in);

    // Der Server erkennt aus der KeyID, welchen AES-Schlüssel er verwenden muss.
    // Falls ihm die KeyID unbekannt ist, so MUSS er mit einer VAUServerError-Nachricht
    // mit der Fehlermeldung "KeyID XXX not found" antworten, wobei er XXX durch die empfangene
    // KeyID
    // in Hexadezimalform ersetzen MUSS.

    if (session == null && !session.isClient()) {
      if (session == null) {
        handleNotRecoverableException(AES_DECRYPTION_ERROR);
      }
    }
    Data decryptedData = null;
    // Falls bei der Entschlüsselung ein Fehler auftritt
    // (bspw. Authentication-Tag passt nicht zur Nachricht),
    // MUSS der Server mit einer VAUServerError-Nachricht mit der Fehlermeldung "AES-GCM decryption
    // error." antworten.
    try {
      logger.info("### VAUProtocol.decrypt ###");
      decryptedData =
          new Data(
              d.keyID,
              crypto.decrypt_AESGCM(
                  d.enc,
                  !session.isClient()
                      ? session.getSymKeyClientToServer()
                      : session.getSymKeyServerToClient(),
                  session.getCounter()));
    } catch (Exception e) {
      handleNotRecoverableException(e, AES_DECRYPTION_ERROR);
    }

    if (!session.isClient()) {
      // Laut Spezifikation prüft der Server nicht, dass der Client immer nur um 1 erhöht
      // Aus diesem Grund kann der Zahlenraum des unsigned long ausgeschöft werden.
      // Das ist beim Vergleich zu berücksichtigen (ist durch die Differenz gewährleistet)

      // Der Server MUSS prüfen, ob der Zählerwert im Klartext größer als der ”Server-
      // Zählerwert” ist. Falls nein, so MUSS der Server (1) eine VAUServerError-Nachricht
      // gemäß A_16851 mit der Fehlermeldung ”invalid counter value” senden und gemäß
      // A_16849 die Protokollausführung abbrechen.
      if (!(decryptedData.counter - session.getCounter() > 0)) {
        handleNotRecoverableException(INVALID_COUNTER_VALUE);
      }

      // Der Server MUSS den ”Server-Zählerwert” auf Zählerwert + 1 setzen.

      session.setCounter(decryptedData.counter + 1);

      logger.info(
          "keyid: "
              + HexUtils.convertToLowerCaseHexWith64ByteLength(session.getKeyID())
              + ", counter for encrypt: "
              + session.getCounter());

      // Falls es dabei zu einem Zählerüberlauf kommt, so MUSS der Server (1) eine
      // VAUServerError-Nachricht gemäß A_16851 mit der Fehlermeldung ”message
      // counter overflow” senden und gemäß A_16849 die Protokollausführung abbrechen.

      // Der größte Counter ist
      // 0b11111111_11111111_11111111_11111111_11111111_11111111_11111111_11111111L;
      // + 1 = 0 ... das war der Überlauf
      //
      if (session.getCounter() == 0) {
        handleNotRecoverableException(MESSAGE_COUNTER_OVERFLOW);
      }
    }

    tryToPersist();
    return decryptedData.getDecryptedData();
  }

  public void handleNotRecoverableException(String errorMessage) {
    logger.error(errorMessage);
    closeSession();
    throw new VAUProtocolException(errorMessage);
  }

  public void handleNotRecoverableException(Exception e, String errorMessage) {
    logger.error(e.getMessage(), e);
    handleNotRecoverableException(errorMessage);
  }

  public void closeSession() {
    if (getPersister() != null) {
      session.setState(VAUProtocolSessionState.closed);
      getPersister().markSessionForClosing(session);
    }
  }

  public void tryToPersist() {
    if (getPersister() != null) {
      getPersister().persist(session);
    }
  }

  public VAUProtocolSessionPersister getPersister() {
    return persister;
  }
}
