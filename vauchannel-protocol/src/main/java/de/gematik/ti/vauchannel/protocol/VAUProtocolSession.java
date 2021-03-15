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
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
@AllArgsConstructor
public class VAUProtocolSession {
  private byte[] keyID;
  private byte[] symKeyClientToServer;
  private byte[] symKeyServerToClient;
  private byte[] clientHelloDataHash;
  private byte[] clientHelloDataCertificateHash;
  private byte[] serverHelloDataHash;
  private KeyPair ephemeralKeyPair;
  private byte[] hash;
  private byte[] share;

  private byte[] authzToken;

  private String recordIDFromAuthzToken;

  private long counter;
  private boolean client;

  // for testing
  private boolean forceErrorInDecryptIfCountIs5;
  private boolean forceErrorInEncryptIfCountIs6;

  private VAUProtocolSessionState state;

  public VAUProtocolSession(boolean client) {
    this.client = client;
    state = VAUProtocolSessionState.handshaking;
  }

  // session is initialized, especially the counter is initialized
  public void initialize() {
    counter = 0L;
    keyID = null;
    symKeyClientToServer = null;
    symKeyServerToClient = null;
    clientHelloDataHash = null;
    serverHelloDataHash = null;
    ephemeralKeyPair = null;
    hash = null;
    share = null;
    authzToken = null;
    recordIDFromAuthzToken = null;
  }
}
