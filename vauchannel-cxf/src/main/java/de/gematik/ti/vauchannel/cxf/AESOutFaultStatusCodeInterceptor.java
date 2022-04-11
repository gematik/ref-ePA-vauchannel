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
package de.gematik.ti.vauchannel.cxf;

import de.gematik.ti.vauchannel.protocol.VAUProtocolException;
import java.util.Map;
import javax.ws.rs.core.Response;
import org.apache.cxf.interceptor.Fault;
import org.apache.cxf.message.Message;
import org.apache.cxf.phase.AbstractPhaseInterceptor;
import org.apache.cxf.phase.Phase;

public class AESOutFaultStatusCodeInterceptor extends AbstractPhaseInterceptor<Message> {
  public AESOutFaultStatusCodeInterceptor() {
    super(Phase.POST_PROTOCOL);
  }

  @SuppressWarnings("unchecked")
  public void handleMessage(Message message) throws Fault {
    Message in = message.getExchange().getInMessage();
    Map<String, Object> headers = (Map<String, Object>) in.get(Message.PROTOCOL_HEADERS);

    message.put(Message.RESPONSE_CODE, Response.Status.OK.getStatusCode());

    String jsonerror = (String) message.getExchange().get("jsonerror");
    if (jsonerror != null
        && (VAUProtocolException.ACCESS_DENIED.equals(jsonerror)
            || VAUProtocolException.CONTEXT_MANAGER_ACCESS_DENIED.equals(jsonerror))) {
      message.put(Message.RESPONSE_CODE, Response.Status.FORBIDDEN.getStatusCode());
    }
  }
}
