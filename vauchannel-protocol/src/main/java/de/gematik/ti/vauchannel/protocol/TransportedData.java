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

import static de.gematik.ti.vauchannel.protocol.VAUProtocolException.SYNTAX_ERROR;
import static de.gematik.ti.vauchannel.protocol.helpers.VAUProtocolHelpers.concat;

import com.google.common.base.Charsets;
import java.nio.ByteBuffer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class TransportedData {

  private static final Logger log = LoggerFactory.getLogger(TransportedData.class);

  public byte[] body;
  public String contentType;

  public TransportedData() {}

  public TransportedData(byte[] body, String contentType) {
    this.body = body;
    this.contentType = contentType;
    log();
  }

  static final String contentTypeDefault = "application/soap+xml";

  public static TransportedData fromRaw(byte[] raw) {
    byte[] numberOfBytes_inBytes = new byte[4];
    System.arraycopy(raw, 0, numberOfBytes_inBytes, 0, 4);
    int numberOfBytes = java.nio.ByteBuffer.wrap(numberOfBytes_inBytes).getInt();
    byte[] headerField_inBytes = new byte[numberOfBytes];
    System.arraycopy(raw, 4, headerField_inBytes, 0, numberOfBytes);
    String headerField = new String(headerField_inBytes, Charsets.US_ASCII);
    int i = headerField.indexOf(":");
    String value = contentTypeDefault; // default-Fall
    if (i > -1) {
      // Transport anderer Header-Felder als "Content-Type" wird von dieser Implementierung
      // nicht unterstützt
      value = headerField.substring(i + 1, headerField.length()).trim();
      String key = headerField.substring(0, i);

      if (!key.equalsIgnoreCase("Content-Type")) {
        throw new VAUProtocolException(SYNTAX_ERROR);
      }
      log.debug(
          "the following content-type header was transported inside the VAU channel: "
              + key
              + ": "
              + value);
    } else {
      log.debug("default content-type header is restored.");
    }
    TransportedData td = new TransportedData();
    td.contentType = value;
    td.body = new byte[raw.length - 4 - numberOfBytes];
    System.arraycopy(raw, 4 + numberOfBytes, td.body, 0, td.body.length);
    td.log();
    return td;
  }

  public byte[] getRaw() {
    String headerField = "";
    if (!contentType.equals(contentTypeDefault)) {
      headerField = "Content-Type: " + contentType;
    }
    byte[] headerField_inBytes = headerField.getBytes(Charsets.US_ASCII);
    byte[] numberOfBytes_inBytes =
        ByteBuffer.allocate(4).putInt(headerField_inBytes.length).array();
    return concat(concat(numberOfBytes_inBytes, headerField_inBytes), this.body);
  }

  public void log() {
    log.info("contentType: " + contentType + "; body length: " + this.body.length);
    log.debug(new String(this.body, Charsets.UTF_8));
  }
}
