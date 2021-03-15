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

import com.google.common.primitives.Longs;
import de.gematik.ti.vauchannel.protocol.TransportedData;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Data {

  private final Logger log = LoggerFactory.getLogger(this.getClass());

  public long counter;
  public byte[] raw;
  public byte[] keyId;
  byte version;

  public Data(byte[] keyId, long counter, TransportedData transportedData) {
    this.keyId = keyId;
    this.counter = counter;
    this.version = 1;
    raw = transportedData.getRaw();
    log();
  }

  public Data(byte[] keyId, byte[] all) {
    this.keyId = keyId;
    version = all[0];
    byte[] rawCounter = new byte[8];
    System.arraycopy(all, 1, rawCounter, 0, 8);
    counter = Longs.fromByteArray(rawCounter);
    raw = new byte[all.length - 8 - 1];
    System.arraycopy(all, 8 + 1, raw, 0, raw.length);
    log();
  }

  public void log() {
    log.info(
        "keyid: "
            + HexUtils.convertToLowerCaseHexWith64ByteLength(this.keyId)
            + ", counter for decrypt: "
            + counter);

    // log.info("keyId: " + Hex.encodeHexString(this.keyId) + "; counter: " + counter); // + "; " +
    // new String(raw, StandardCharsets.UTF_8));
  }

  public byte[] getEncoded() {
    return concat(new byte[] {this.version}, concat(Longs.toByteArray(counter), raw));
  }

  public TransportedData getDecryptedData() {
    return TransportedData.fromRaw(this.raw);
  }
}
