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
package de.gematik.ti.vauchannel.protocol.sign;

import static org.junit.Assert.assertTrue;

import de.gematik.ti.vauchannel.protocol.helpers.Base64;
import de.gematik.ti.vauchannel.protocol.helpers.Identity;
import de.gematik.ti.vauchannel.protocol.helpers.VAUProtocolCryptoImpl;
import org.junit.*;

/** @author matth */
public class SignerTest {

  public SignerTest() {}

  @BeforeClass
  public static void setUpClass() {}

  @AfterClass
  public static void tearDownClass() {}

  @Before
  public void setUp() {}

  @After
  public void tearDown() {}

  /** Test of signECDSA method, of class Signer. */
  @Test
  public void testSignVerifyECDSA() throws Exception {
    Identity identity = Identity.generateSelfSigned_ECC();
    VAUProtocolCryptoImpl crypto = new VAUProtocolCryptoImpl(true, identity);
    byte[] message = "My message".getBytes();
    byte[] result = crypto.signECDSA(message);
    System.out.println("ECDSA:");
    System.out.println(Base64.encode2String(result));
    boolean ok = crypto.verify(message, result, identity.certificate.getPublicKey());
    assertTrue(ok);
  }

  @Test
  public void testSignVerifyRSASSA_PSS() throws Exception {
    Identity identity = Identity.generateSelfSigned_RSA();
    VAUProtocolCryptoImpl crypto = new VAUProtocolCryptoImpl(false, identity);
    byte[] message = "My message".getBytes();
    byte[] result = crypto.signRSASSA_PSS(message);
    System.out.println("RSASSA_PSS:");
    System.out.println(Base64.encode2String(result));
    boolean ok = crypto.verify(message, result, identity.certificate.getPublicKey());
    assertTrue(ok);
  }
}
