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
package de.gematik.ti.vauchannel.server;

import de.gematik.ti.vauchannel.cxf.HandshakeRSJsonInterface;
import de.gematik.ti.vauchannel.protocol.VAUProtocol;
import javax.ws.rs.Path;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.validation.annotation.Validated;

@Path("")
@Validated
public class HandshakeRSJson implements HandshakeRSJsonInterface {
  private final Logger logger = LoggerFactory.getLogger(this.getClass());

  @Autowired SimpleVAUProtocolProvider vauProtocolProvider;

  @Override
  public String process(String in) {
    VAUProtocol server = null;
    String message = null;
    try {
      if (in != null && !in.contains("VAUClientSigFin")) {
        // vauProtocolProvider.resetVAUProtocol("");  // for testing
        server = vauProtocolProvider.getVAUProtocol("");
        message = server.handshakeStep2_generate_VAUServerHello_Message(in);
      } else {
        server = vauProtocolProvider.getVAUProtocol("");
        message = server.handshakeStep4_generate_VAUServerFin_Message(in);
      }
    } catch (Exception e) {
      message = e.getMessage();
      if (server != null) {
        message = server.generateVAUServerErrorMessage(message);
      }
      logger.error(e.getMessage(), e);
    }
    return message;
  }
}
