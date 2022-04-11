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

import de.gematik.ti.vauchannel.cxf.SomeServiceInterface;
import de.gematik.ti.vauchannel.protocol.VAUProtocolException;
import javax.jws.WebService;
import org.apache.cxf.phase.PhaseInterceptorChain;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;

@WebService()
public class SomeService implements SomeServiceInterface {
  private final Logger log = LoggerFactory.getLogger(this.getClass());

  @Autowired SimpleVAUProtocolProvider vauProtocolProvider;

  public String sayHello(String helloFromClient) {
    log.info("got from client: " + helloFromClient);
    return "hello from server";
  }

  public void throwAnException(String message) throws Exception {
    if (VAUProtocolException.ACCESS_DENIED.equals(message)) {
      PhaseInterceptorChain.getCurrentMessage()
          .getExchange()
          .put("jsonerror", VAUProtocolException.ACCESS_DENIED);
    }
    throw new Exception(message);
  }

  public void closeVAUSession() {
    vauProtocolProvider.getVAUProtocol("").closeSession();
  }
}
