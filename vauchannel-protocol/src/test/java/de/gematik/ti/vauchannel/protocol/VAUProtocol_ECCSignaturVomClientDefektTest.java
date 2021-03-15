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

import static de.gematik.ti.vauchannel.protocol.helpers.Base64.decode;
import static de.gematik.ti.vauchannel.protocol.helpers.Base64.encode2String;
import static de.gematik.ti.vauchannel.protocol.helpers.ObjectMapperFactory.objectMapper;
import static org.junit.Assert.assertEquals;

import com.fasterxml.jackson.databind.ObjectMapper;
import de.gematik.rs.vau.VAUClientSigFin;
import de.gematik.rs.vau.VAUServerError;
import de.gematik.rs.vau.VAUServerErrorData;
import de.gematik.ti.vauchannel.protocol.helpers.VAUProtocolCryptoImpl;
import de.gematik.ti.vauchannel.protocol.helpers.VAUProtocolHelpers;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Before;
import org.junit.Test;

// [17072]
public class VAUProtocol_ECCSignaturVomClientDefektTest {

  static {
    Security.addProvider(new BouncyCastleProvider());
  }

  ObjectMapper mapper = objectMapper();
  VAUProtocol client;
  VAUProtocol server;

  @Before
  public void initialize() throws Exception {
    server = new VAUProtocol(new VAUProtocolCryptoImpl(true), new VAUProtocolSession(false));
    client = new VAUProtocol(new VAUProtocolCryptoImpl(true), new VAUProtocolSession(true));
  }

  @Test
  public void handshake() throws Exception {

    String vAUClientHelloStr = client.handshakeStep1_generate_VAUClientHello_Message(null);
    VAUProtocolHelpers.logJSON(vAUClientHelloStr);

    String vAUServerHelloStr =
        server.handshakeStep2_generate_VAUServerHello_Message(vAUClientHelloStr);
    VAUProtocolHelpers.logJSON(vAUServerHelloStr);

    String vAUClientSigFinStr =
        client.handshakeStep3_generate_VAUClientSigFin_Message(vAUServerHelloStr);
    VAUProtocolHelpers.logJSON(vAUClientSigFinStr);

    VAUClientSigFin vAUClientSigFin = mapper.readValue(vAUClientSigFinStr, VAUClientSigFin.class);
    byte[] sigBytes = decode(vAUClientSigFin.getSignature());
    if (sigBytes[0] == (byte) 2) {
      sigBytes[0] = (byte) 3;
    } else {
      sigBytes[0] = (byte) 2;
    }
    vAUClientSigFin.setSignature(encode2String(sigBytes));
    String vAUClientSigFinStr_Wrong = mapper.writeValueAsString(vAUClientSigFin);

    String serverResponse =
        server.handshakeStep4_generate_VAUServerFin_Message(vAUClientSigFinStr_Wrong);
    VAUServerError vauServerError = mapper.readValue(serverResponse, VAUServerError.class);
    assertEquals(vauServerError.getMessageType().value(), "VAUServerError");
    VAUServerErrorData vauServerErrorData =
        mapper.readValue(decode(vauServerError.getData()), VAUServerErrorData.class);

    assertEquals(vauServerErrorData.getDataType().value(), "VAUServerErrorData");
    assertEquals(vauServerErrorData.getData(), "Signature from VAUClientSigFin invalid");
  }
}
