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

import static de.gematik.ti.vauchannel.protocol.helpers.VAUProtocolHelpers.checkClientSignature;
import static de.gematik.ti.vauchannel.protocol.helpers.VAUProtocolHelpers.checkServerSignature;

import com.fasterxml.jackson.databind.ObjectMapper;
import de.gematik.rs.vau.VAUClientSigFin;
import de.gematik.rs.vau.VAUServerHello;
import de.gematik.ti.vauchannel.protocol.helpers.VAUProtocolCryptoImpl;
import de.gematik.ti.vauchannel.protocol.helpers.VAUProtocolHelpers;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class VAUProtocolEncryptDecryptTest {

  static {
    Security.addProvider(new BouncyCastleProvider());
  }

  ObjectMapper mapper = new ObjectMapper();
  VAUProtocol client;
  VAUProtocol server;

  @Before
  public void initialize() throws Exception {
    server = new VAUProtocol(new VAUProtocolCryptoImpl(true), new VAUProtocolSession(false));
    client = new VAUProtocol(new VAUProtocolCryptoImpl(true), new VAUProtocolSession(true));
    handshake();
  }

  @Test
  public void encryptDecrypt() {

    final byte[] exampleContent = "do not change".getBytes();
    ;
    final String exampleContentType = "my : content : type";

    Assert.assertArrayEquals(client.session().getShare(), server.session().getShare());
    Assert.assertArrayEquals(
        client.session().getSymKeyClientToServer(), server.session().getSymKeyClientToServer());
    Assert.assertArrayEquals(
        client.session().getSymKeyServerToClient(), server.session().getSymKeyServerToClient());
    Assert.assertArrayEquals(client.session().getKeyID(), server.session().getKeyID());

    TransportedData transportedData = new TransportedData();
    transportedData.body = exampleContent;
    transportedData.contentType = exampleContentType;

    byte[] encBytes = client.encrypt(transportedData);
    transportedData = null;

    transportedData = server.decrypt(encBytes);

    Assert.assertEquals(transportedData.contentType, exampleContentType);
    Assert.assertArrayEquals(transportedData.body, exampleContent);

    encBytes = server.encrypt(transportedData);

    transportedData = client.decrypt(encBytes);

    Assert.assertEquals(transportedData.contentType, exampleContentType);
    Assert.assertArrayEquals(transportedData.body, exampleContent);
  }

  public void handshake() throws Exception {

    String vAUClientHelloStr = client.handshakeStep1_generate_VAUClientHello_Message(null);
    VAUProtocolHelpers.logJSON(vAUClientHelloStr);

    String vAUServerHelloStr =
        server.handshakeStep2_generate_VAUServerHello_Message(vAUClientHelloStr);
    VAUProtocolHelpers.logJSON(vAUServerHelloStr);

    String vAUClientSigFinStr =
        client.handshakeStep3_generate_VAUClientSigFin_Message(vAUServerHelloStr);
    VAUProtocolHelpers.logJSON(vAUClientSigFinStr);

    String vAUServerFinStr =
        server.handshakeStep4_generate_VAUServerFin_Message(vAUClientSigFinStr);
    VAUProtocolHelpers.logJSON(vAUServerFinStr);

    checkServerSignature(
        mapper.readValue(vAUServerHelloStr, VAUServerHello.class), client.crypto());
    checkClientSignature(
        mapper.readValue(vAUClientSigFinStr, VAUClientSigFin.class), server.crypto());

    client.handshakeStep5_validate_VAUServerFin_Message(vAUServerFinStr);
  }
}
