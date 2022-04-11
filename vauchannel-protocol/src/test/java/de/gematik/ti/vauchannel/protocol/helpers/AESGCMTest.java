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
package de.gematik.ti.vauchannel.protocol.helpers;

import static org.junit.Assert.*;

import java.io.FileInputStream;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.io.IOUtils;
import org.junit.Assert;
import org.junit.Test;

public class AESGCMTest {

  @Test
  public void generateIV() {
    byte[] iv = AESGCM.generateIV(1L);
    Assert.assertEquals(iv[4], 0);
    Assert.assertEquals(iv[11], 1);
  }

  @Test
  public void decryptMTOMRequest() throws Exception {
    byte[] symkey =
        Hex.decodeHex("0D6770DCAA6197F233D19028910329FEA837BC2063BA9AE4858AE1047BF67699");
    byte[] request = IOUtils.toByteArray(new FileInputStream("src/test/resources/request.bin"));
    EncData d = new EncData(request);
    VAUProtocolCryptoImpl crypto = new VAUProtocolCryptoImpl();
    Data decryptedData = new Data(d.keyID, crypto.decrypt_AESGCM(d.enc, symkey, -1));
    String bodyString = new String(decryptedData.getDecryptedData().body, "UTF-8");
    System.out.println(bodyString);
  }
}
