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
package de.gematik.ti.vauchannel.protocol;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.crypto.DataLengthException;

public interface VAUProtocolCrypto {

  LocalDateTime now();

  byte[] hash(byte[] in);

  byte[] ECKA(PrivateKey prk, PublicKey puk) throws Exception;

  byte[] HKDF(byte[] ikm, String info, int length)
      throws IllegalArgumentException, DataLengthException;

  byte[] HKDF(byte[] ikm, byte[] info, int length)
      throws IllegalArgumentException, DataLengthException;

  byte[] signRSASSA_PSS(byte[] message) throws Exception;

  boolean verify(byte[] message, byte[] signatureBytes, PublicKey puk);

  byte[] signECDSA(byte[] message) throws Exception;

  KeyPair generateECCKeyPair();

  PublicKey eccPublicKeyFromBytes(byte[] pubKey);

  OCSPResp getOcspResponse();

  X509Certificate getEECertificate();

  boolean isECCIdentity();

  boolean canProvideOcspResponse();

  byte[] encrypt_AESGCM(byte[] encoded, byte[] symKey, long counter) throws Exception;

  byte[] decrypt_AESGCM(byte[] enc, byte[] symKey, long counter) throws Exception;

  /**
   * Prüfungen gemäß den Vorgaben in [gemSpec_Dokumentenverwaltung]
   *
   * <p>A_17387 - Komponente ePA-Dokumentenverwaltung – Authorization Assertion-Validierung Die
   * Komponente ePA-Dokumentenverwaltung MUSS sicherstellen, dass Authorization Assertions nur
   * akzeptiert werden, wenn das zugehörige Signaturzertifikat zeitlich gültig ist, nicht gesperrt
   * wurde und nach dem Zertifikatsprofil C.FD.SIG auf die Identität der Komponente Autorisierung
   * ausgestellt wurde.
   *
   * <p>A_14633 - Komponente ePA-Dokumentenverwaltung – Vermittlung der Verbindung zwischen Client
   * und Verarbeitungskontext Das Kontextmanagement der Komponente ePA-Dokumentenverwaltung MUSS die
   * Verbindung zwischen Client, d.h. dem ePA-Modul Frontend des Versicherten bzw. dem Fachmodul ePA
   * oder Fachmodul ePA KTR-Consumer, und Verarbeitungskontext vermitteln und dabei • die
   * Base64-dekodierte Authorization Assertion der VAUClientHello-Nachricht auf Gültigkeit gemäß
   * Anforderung A_13690 sowie auf den gültigen Berechtigungstyp (AuthorizationType =
   * "DOCUMENT_AUTHORIZATION") prüfen und bei ungültiger Authorization Assertion den
   * Verbindungsaufbau abbrechen und mit dem HTTP-Fehler 403 antworten, • den Record Identifier des
   * Verarbeitungskontextes über den Wert des Attributs Resource ID aus der Authorization Assertion
   * der VAUClientHello-Nachricht ermitteln, • für Clients vom Typ ePA-Modul Frontend des
   * Versicherten die Verbindung auf der Grundlage des vom Zugangsgateway gesetzten HTTP
   * Header-Feldes Session registrieren, • für Clients vom Typ Fachmodul ePA die Verbindung auf
   * Grundlage der TLS-Sitzung registrieren, • während der Dauer der Sitzung alle eingehenden
   * Requests auf der Grundlage der registrierten Verbindung an den Zielverarbeitungskontext
   * weiterleiten sowie • nach dem Ende der Sitzung, aufgrund eines Timeouts bzw. aufgrund einer
   * Beendigung durch den Nutzer, die Registrierung der Verbindung löschen.
   *
   * @param vauProtocolSession
   * @param authorizationAssertionStr base64 encoded
   */
  void validateAuthorizationAssertion(
      VAUProtocolSession vauProtocolSession, String authorizationAssertionStr);

  void checkServerCertificate(X509Certificate cert);

  /**
   * Führt eine OCSP-Überprüfung für das vorliegende Zertifikat durch. Im Fehlerfall wird eine
   * Exception geworfen.
   *
   * @param cert Das zu prüfende Zertifikat
   * @throws Exception Im Falle einer fehlgeschlagenen oder fehlerhaften OCSP-Überprüfung
   */
  void performOcspCheckForCertificate(X509Certificate cert) throws Exception;

  /**
   * Führt eine TSL-Überprüfung für das vorliegende Zertifikat durch. Im Fehlerfall wird eine
   * Exception geworfen. Die Prüfung erfolgt analog zu A_15873 Punkt 2
   *
   * @param cert Das zu prüfende Zertifikat
   * @throws Exception Im Falle einer fehlgeschlagenen oder fehlerhaften TSL-Überprüfung
   */
  void performTslCheckForCertificate(X509Certificate cert) throws Exception;
}
