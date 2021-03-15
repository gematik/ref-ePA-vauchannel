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

import static de.gematik.ti.vauchannel.protocol.helpers.ObjectMapperFactory.objectMapper;
import static org.junit.Assert.assertEquals;

import com.fasterxml.jackson.databind.ObjectMapper;
import de.gematik.rs.vau.VAUClientHello;
import de.gematik.rs.vau.VAUClientHelloData;
import de.gematik.rs.vau.VAUServerError;
import de.gematik.rs.vau.VAUServerErrorData;
import de.gematik.ti.vauchannel.protocol.helpers.Base64;
import de.gematik.ti.vauchannel.protocol.helpers.KeyPairGenerator;
import de.gematik.ti.vauchannel.protocol.helpers.VAUProtocolCryptoImpl;
import de.gematik.ti.vauchannel.protocol.helpers.VAUProtocolHelpers;
import java.nio.charset.StandardCharsets;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Before;
import org.junit.Test;

public class VAUProtocol_FalscheKurveTest {

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

  public String step1Wrong(VAUProtocolSession c, byte[] authzToken) throws Exception {
    VAUClientHello vAUClientHello = step1Wrong_(c, authzToken);

    String vAUClientHelloStr_Again = mapper.writeValueAsString(vAUClientHello);
    vAUClientHelloStr_Again += "";
    return vAUClientHelloStr_Again;
  }

  public VAUClientHello step1Wrong_(VAUProtocolSession clientSession, byte[] authzToken)
      throws Exception {
    VAUClientHelloData vAUClientHelloData = new VAUClientHelloData();
    vAUClientHelloData.setDataType(VAUClientHelloData.DataType.VAU_CLIENT_HELLO_DATA);
    vAUClientHelloData.setCipherConfiguration(VAUProtocolHelpers.getCipherConfiguration());

    byte[] certBytes = client.crypto().getEECertificate().getEncoded();
    String certHash = Base64.encode2String(client.crypto().hash(certBytes));
    vAUClientHelloData.setCertificateHash(certHash);

    if (authzToken != null) {
      vAUClientHelloData.setAuthorizationAssertion(Base64.encode2String(authzToken));
    }

    clientSession.setEphemeralKeyPair(KeyPairGenerator.generateECCKeyPair("brainpoolp384r1"));
    vAUClientHelloData.setPublicKey(
        Base64.encode2String(clientSession.getEphemeralKeyPair().getPublic().getEncoded()));
    VAUClientHello vAUClientHello = new VAUClientHello();
    vAUClientHello.setMessageType(VAUClientHello.MessageType.VAU_CLIENT_HELLO);
    String vAUClientHelloDataStr = mapper.writeValueAsString(vAUClientHelloData);
    byte[] data = Base64.encode(vAUClientHelloDataStr.getBytes(StandardCharsets.UTF_8));
    vAUClientHello.setData(new String(data, StandardCharsets.UTF_8));
    clientSession.setClientHelloDataHash(new VAUProtocolCryptoImpl().hash(data));
    return vAUClientHello;
  }

  @Test
  public void handshake() throws Exception {

    String vAUClientHelloStr = step1Wrong(client.session(), null);
    VAUProtocolHelpers.logJSON(vAUClientHelloStr);

    String serverResponse =
        server.handshakeStep2_generate_VAUServerHello_Message(vAUClientHelloStr);

    VAUServerError vauServerError = mapper.readValue(serverResponse, VAUServerError.class);
    assertEquals(vauServerError.getMessageType().value(), "VAUServerError");
    VAUServerErrorData vauServerErrorData =
        mapper.readValue(Base64.decode(vauServerError.getData()), VAUServerErrorData.class);

    assertEquals(vauServerErrorData.getDataType().value(), "VAUServerErrorData");
    assertEquals(vauServerErrorData.getData(), "invalid curve (ECDH)");
  }
}
