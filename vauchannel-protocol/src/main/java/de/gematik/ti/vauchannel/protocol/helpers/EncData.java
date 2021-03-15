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

import static de.gematik.ti.vauchannel.protocol.helpers.VAUProtocolHelpers.concat;

public class EncData {
  public byte[] keyID;
  public byte[] enc;

  public EncData(byte[] keyID, byte[] enc) {
    this.keyID = keyID;
    this.enc = enc;
  }

  public EncData(byte[] all) {
    keyID = new byte[32];
    System.arraycopy(all, 0, keyID, 0, 32);
    enc = new byte[all.length - 32];
    System.arraycopy(all, 32, enc, 0, all.length - 32);
  }

  public byte[] getEncoded() {
    return concat(keyID, enc);
  }
}
