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
package de.gematik.ti.vauchannel.client;


import de.gematik.ti.vauchannel.cxf.VAUProtocolProvider;
import de.gematik.ti.vauchannel.protocol.VAUProtocol;
import de.gematik.ti.vauchannel.protocol.VAUProtocolSession;
import de.gematik.ti.vauchannel.protocol.helpers.VAUProtocolCryptoImpl;
import org.apache.cxf.message.Message;
import org.springframework.stereotype.Component;

import java.security.cert.X509Certificate;

// Handling of session information is not part of the vauchannel module
// The following implementation is naive in the sense that there should be actually
// the VAUProtocolSession session info per session not one globally
@Component
public class SimpleClientVAUProtocolProvider implements VAUProtocolProvider {
    private VAUProtocol vauProtocol;

    public SimpleClientVAUProtocolProvider() {
    }

    @Override
    public VAUProtocol getVAUProtocol() {
        if (this.vauProtocol == null) {
            vauProtocol = new VAUProtocol(new VAUProtocolCryptoImpl(true), new VAUProtocolSession(true));
        }
        return this.vauProtocol;
    }

    @Override
    public VAUProtocol getVAUProtocolByKeyID(byte[] keyID) {
        return getVAUProtocol();
    }

    @Override
    public VAUProtocol getVAUProtocol(X509Certificate cert) {
        return getVAUProtocol();
    }

    @Override
    public VAUProtocol getVAUProtocol(String someIdentifier) {
        return getVAUProtocol();
    }

    @Override
    public void closeVAUProtocol(VAUProtocol vauProtocol) {
        this.vauProtocol = null;
    }


    @Override
    public boolean isClient() {
        return true;
    }



}
