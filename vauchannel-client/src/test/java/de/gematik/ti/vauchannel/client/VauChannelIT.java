/*
 * Copyright (c) 2019 gematik - Gesellschaft für Telematikanwendungen der Gesundheitskarte mbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package de.gematik.ti.vauchannel.client;

import com.fasterxml.jackson.databind.ObjectMapper;
import de.gematik.ti.vauchannel.cxf.HandshakeRSJsonInterface;
import de.gematik.ti.vauchannel.cxf.SomeServiceInterface;
import de.gematik.ti.vauchannel.protocol.VAUProtocol;
import de.gematik.ti.vauchannel.protocol.VAUProtocolException;
import org.apache.cxf.binding.soap.SoapFault;
import org.apache.cxf.transport.http.HTTPException;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;

import javax.xml.ws.soap.SOAPFaultException;

import static de.gematik.ti.vauchannel.protocol.helpers.ObjectMapperFactory.objectMapper;

@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
public class VauChannelIT {
    private final Logger logger = LoggerFactory.getLogger(VauChannelIT.class);
    @Autowired
    SimpleClientVAUProtocolProvider vauProtocolProvider;
    @Autowired
    SomeServiceInterface someService;
    @Autowired
    HandshakeRSJsonInterface handshakeServer;
    ObjectMapper mapper = objectMapper();

    private void close(VAUProtocol client) {
        someService.closeVAUSession();
        vauProtocolProvider.closeVAUProtocol(client);
    }

    public void testGF() throws Exception {
        VAUProtocol client = vauProtocolProvider.getVAUProtocol("");
        vAUProtocolHandshake(client, null);
        sayHello();
        close(client);
    }

    @Test
    public void GF() throws Exception {
        testGF();
    }

    @Test
    public void GF_2x() throws Exception {
        testGF();
        testGF();
    }



    @Test
    public void SF_sendRequestAfterClosingSessionOnServer() throws Exception {
        VAUProtocol client = vauProtocolProvider.getVAUProtocol("");
        vAUProtocolHandshake(client, null);
        sayHello();
        someService.closeVAUSession();
        try {
            sayHello();
            Assert.assertTrue(false);
        } catch (SOAPFaultException e) {
            vauProtocolProvider.closeVAUProtocol(client);
            Assert.assertEquals("Access Denied", e.getFault().getFaultString());
            SoapFault cause = (SoapFault)e.getCause();
            Assert.assertEquals(403, cause.getStatusCode());
        }
        testGF();
    }

    @Test
    public void GF_ExceptionFromService() throws Exception {
        VAUProtocol client = vauProtocolProvider.getVAUProtocol("");
        vAUProtocolHandshake(client, null);
        String errorMessage = "exception from service";
        try {
            someService.throwAnException(errorMessage);
            Assert.assertTrue(false);
        } catch (Exception e) {
            logger.error(e.getMessage(), e);
            Assert.assertTrue(e.getMessage().equals(errorMessage));
        }
        close(client);
    }

    @Test
    public void GF_AccessDeniedFromService() {
        VAUProtocol client = vauProtocolProvider.getVAUProtocol("");
        vAUProtocolHandshake(client, null);
        try {
            someService.throwAnException(VAUProtocolException.ACCESS_DENIED);
            Assert.assertTrue(false);
        } catch (Exception e) {
            logger.error(e.getMessage(), e);
            vauProtocolProvider.closeVAUProtocol(client);
            Assert.assertEquals("Access Denied", e.getMessage());
            SoapFault sf = (SoapFault)e;
            Assert.assertEquals(403, sf.getStatusCode());
        }

    }

    @Test
    public void GF_AccessDeniedFromServiceThenAgainServiceCall() {
        VAUProtocol client = vauProtocolProvider.getVAUProtocol("");
        vAUProtocolHandshake(client, null);
        try {
            someService.throwAnException(VAUProtocolException.ACCESS_DENIED);
        } catch (Exception e) {
        }
        try {
            sayHello();
            Assert.assertTrue(false);
        } catch (Exception e) {
            logger.error(e.getMessage(), e);
            Assert.assertTrue(true);
            vauProtocolProvider.closeVAUProtocol(client);
        }
    }

    @Test
    public void SF_noHandshake_hello() throws Exception {
        String result = null;
        try {
            result = someService.sayHello("hello from integration client");
            Assert.assertTrue(false);
        } catch (Exception e) {
            logger.error(e.getMessage(), e);
            HTTPException cause = (HTTPException)e.getCause();
            Assert.assertEquals(403, cause.getResponseCode());
        }
    }


    public VAUProtocol vAUProtocolHandshake(VAUProtocol client, byte[] authzToken) {
        logger.info("starting vau protocol handshake ...");
        String vAUClientHello = client.handshakeStep1_generate_VAUClientHello_Message(authzToken);
        String vAUServerHello = handshakeServer.process(vAUClientHello);
        String vAUClientSigFin = client.handshakeStep3_generate_VAUClientSigFin_Message(vAUServerHello);
        String vAUServerFin = handshakeServer.process(vAUClientSigFin);
        client.handshakeStep5_validate_VAUServerFin_Message(vAUServerFin);
        logger.info("... vau protocol handshake finished");
        return client;
    }

    public void sayHello() {
        String result = someService.sayHello("hello from integration client");
        logger.info("Got response from server: " + result);
    }

    @Test
    public void SF_forcedDecryptionErrorOnServer() throws Exception {
        VAUProtocol client = vauProtocolProvider.getVAUProtocol("");
        vAUProtocolHandshake(client, null);
        sayHello();
        sayHello();
        logger.info("Error will be forced during decryption on server.");
        logger.info("On serverSession it has been set");
        logger.info("serverSession.setForceErrorInDecryptIfCountLarger4(true);");
        try {
            sayHello();
            Assert.assertTrue(false);
        } catch (SOAPFaultException e) {
            Assert.assertEquals("error has been forced by configuration", e.getFault().getFaultString());
            vauProtocolProvider.closeVAUProtocol(client);
        }
        try {
            sayHello();
            Assert.assertTrue(false);
        } catch (Exception e) {
            logger.error(e.getMessage(), e);
            HTTPException cause = (HTTPException)e.getCause();
            Assert.assertEquals(403, cause.getResponseCode());
        }
        testGF();
    }

    @Test
    public void SF_forcedEncryptionErrorOnServer() throws Exception {
        VAUProtocol client = vauProtocolProvider.getVAUProtocol("");
        vAUProtocolHandshake(client, null);
        sayHello();
        sayHello();
        logger.info("Error will be forced during encryption on client. The following ERROR plus Stacktrace is expected.");
        vauProtocolProvider.getVAUProtocol("").session().setForceErrorInEncryptIfCountIs6(true);
        try {
            sayHello();
            Assert.assertTrue(false);
        } catch (SOAPFaultException e) {
            Assert.assertEquals("error has been forced by configuration", e.getFault().getFaultString());
            vauProtocolProvider.closeVAUProtocol(client);
        }
        try {
            sayHello();
            Assert.assertTrue(false);
        } catch (Exception e) {
            logger.error(e.getMessage(), e);
            HTTPException cause = (HTTPException)e.getCause();
            Assert.assertEquals(403, cause.getResponseCode());
        }
        testGF();
    }

}
