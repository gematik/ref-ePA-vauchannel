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

import static de.gematik.ti.vauchannel.cxf.SOAPHelper.writeErrorStringToMessage;
import static de.gematik.ti.vauchannel.cxf.VAUMessageContext.*;
import static org.apache.cxf.helpers.HttpHeaderHelper.findCharset;

import de.gematik.ti.vauchannel.protocol.*;
import de.gematik.ti.vauchannel.protocol.helpers.Base64;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import org.apache.commons.codec.Charsets;
import org.apache.commons.codec.binary.Hex;
import org.apache.cxf.binding.soap.SoapFault;
import org.apache.cxf.interceptor.Fault;
import org.apache.cxf.io.CachedOutputStream;
import org.apache.cxf.message.Message;
import org.apache.cxf.phase.AbstractPhaseInterceptor;
import org.apache.cxf.transport.http.AbstractHTTPDestination;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;

public class AESInterceptor extends AbstractPhaseInterceptor<Message> {

  private final Logger log = LoggerFactory.getLogger(this.getClass());
  @Autowired VAUProtocolProvider vauProtocolProvider;

  @Autowired(required = false)
  DecryptedHTTPMessageLogger decryptedHTTPMessageLogger;

  public AESInterceptor(String phase) {
    super(phase);
  }

  public void handleMessage(Message message) {
    String errorMessage = (String) message.getExchange().get("jsonerror");
    if (errorMessage == null) {
      try {
        handleVauProtocolAES(message);
      } catch (org.apache.cxf.transport.http.HTTPException he) {
        if (he.getResponseCode() == 403) {
          log.error("got HTTP status code 403 -> access denied");
        }
        Fault f = new SoapFault("Access Denied", SoapFault.FAULT_CODE_CLIENT);
        f.setStatusCode(he.getResponseCode());
        throw f;
      } catch (Exception e) {
        log.error(e.getMessage(), e);
        handleExceptionInEncryptionLayer(message, e);
      }
    } else {
      try {
        handleVauProtocolError(message, errorMessage);
      } catch (Exception e) {
        log.error(e.getMessage(), e);
      }
    }
  }

  public void handleFault(Message message) {}

  @java.lang.SuppressWarnings("java:S1143")
  public void handleVauProtocolAES(Message message) throws Exception {
    String contentType = (String) message.get("Content-Type");

    if (vauProtocolProvider.isClient()) {
      VAUProtocol vauProtocol = vauProtocolProvider.getVAUProtocol();
      Object o = message.get("org.apache.cxf.message.inbound");
      if (o != null && (Boolean) o) {
        if (contentType != null && contentType.startsWith("application/json")) {
          byte[] rawData = readContentFromMessage(message);
          String serverError = new String(rawData);
          log.info(serverError);
          String errorString = vauProtocol.validateAndUnpackServerError(serverError);
          log.info(errorString);
          writeErrorStringToMessage(errorString, message);
        }
      }
    }

    // [A_16884] - VAU-Protokoll: Nachrichtentypen und HTTP-Content-Type

    if (contentType != null && contentType.startsWith("application/json")) {
      return;
    }

    boolean isOutbound =
        message == message.getExchange().getOutMessage()
            || message == message.getExchange().getOutFaultMessage();

    VAUMessageContext vauMessageContext = VAU_CHANNEL_NOT_ALLOWED;
    if (contentType != null && contentType.startsWith("application/json")) {
      vauMessageContext = VAU_CHANNEL_HANDSHAKE;
    } else if (isOutbound) {
      vauMessageContext = VAU_CHANNEL_TRANSPORT;
    } else if (contentType != null && contentType.startsWith("application/octet-stream")) {
      vauMessageContext = VAU_CHANNEL_TRANSPORT;
    }

    if (vauMessageContext == VAU_CHANNEL_NOT_ALLOWED) {
      String errorMessage = VAUProtocolException.CONTEXT_MANAGER_ACCESS_DENIED;
      log.error(errorMessage);
      handleExceptionInEncryptionLayer(message, errorMessage);
    }

    if (isOutbound) {

      VAUProtocol vauProtocol = vauProtocolProvider.getVAUProtocol();
      VAUProtocolSession session = vauProtocol.session();

      if (session.isClient()
          && vauMessageContext == VAU_CHANNEL_TRANSPORT
          && session.getSymKeyClientToServer() == null) {
        throw new VAUProtocolException(VAUProtocolException.ACCESS_DENIED);
      }
      //            if (!session.isClient() && session.getCounter() == 0) {
      //                session.setCounter(0);
      //            }
      OutputStream os = message.getContent(OutputStream.class);
      CachedStream cs = new CachedStream();
      message.setContent(OutputStream.class, cs);
      message.getInterceptorChain().doIntercept(message);

      try {
        cs.flush();

        String originalContentType = (String) message.get("Content-Type");
        String encoding = (String) message.get("org.apache.cxf.message.Message.ENCODING");
        if (encoding != null) {
          originalContentType += "; charset=" + encoding;
        }

        Map<String, List> headers = (Map<String, List>) message.get(Message.PROTOCOL_HEADERS);
        if (headers == null) {
          headers = new HashMap<>();
          message.put(Message.PROTOCOL_HEADERS, headers);
        }

        message.put("org.apache.cxf.message.Message.ENCODING", null);
        message.put("Content-Type", "application/octet-stream"); // [A_16884]

        CachedOutputStream csNew = (CachedOutputStream) message.getContent(OutputStream.class);

        message.setContent(OutputStream.class, os);

        byte[] rawMessageData = csNew.getBytes();
        byte[] finalMessageData = null;

        if (!session.isClient() && isAccessDeniedException(rawMessageData)) {

          if (isAccessDeniedExceptionByVAU(rawMessageData)) {
            log.info("access denied by vau");
            String errorStr =
                vauProtocol.generateVAUServerErrorMessage(VAUProtocolException.ACCESS_DENIED);
            message.put("Content-Type", "application/json"); // [A_16884]
            finalMessageData = errorStr.getBytes(Charsets.UTF_8);
          } else {
            log.info("access denied by context manager");
          }
          message.put(Message.RESPONSE_CODE, 403);
          session.setState(VAUProtocolSessionState.closing);
        } else {
          if (this.decryptedHTTPMessageLogger != null)
            this.decryptedHTTPMessageLogger.logMessage(!isOutbound, message, rawMessageData);
          TransportedData transportedData =
              new TransportedData(rawMessageData, originalContentType);
          finalMessageData = vauProtocol.encrypt(transportedData);
        }

        if (!session.isClient() && session.getState() == VAUProtocolSessionState.closing) {
          session.setState(VAUProtocolSessionState.closed);
          this.vauProtocolProvider.closeVAUProtocol(vauProtocol);
        }
        os.write(finalMessageData, 0, finalMessageData.length);

      } catch (IOException e) {
        if (session != null) {
          log.error(e.getMessage(), e);
        }
      } finally {
        if (vauProtocol != null) {
          vauProtocol.tryToPersist();
        }
        try {
          cs.close();
          os.flush();
          os.close();
        } catch (org.apache.cxf.transport.http.HTTPException he) {
          if (session.isClient() && he.getResponseCode() == 403) {
            log.error("got HTTP status code 403 -> access denied");
          }
          throw he;
        } catch (Exception e) {
          log.error(e.getMessage(), e);
        }
      }
    } else {
      byte[] rawRequest = readContentFromMessage(message);

      VAUProtocol vauProtocol = null;
      byte[] keyID = null;
      try {
        keyID = VAUProtocol.getKeyIDFromRawRequest(rawRequest);
        vauProtocol = vauProtocolProvider.getVAUProtocolByKeyID(keyID);
      } catch (Exception e) {
        log.error(e.getMessage());
        log.info("KeyID (Base64): " + Base64.encode2String(keyID));
        log.info("KeyID (Hex): " + Hex.encodeHexString(keyID));
        log.info("Message: \n" + Base64.encode2String(rawRequest));
        throw new VAUProtocolException(VAUProtocolException.INTERNAL_SERVER_ERROR);
      }

      VAUProtocolSession session = vauProtocol.session();

      if (session.getState() == VAUProtocolSessionState.handshaking
          || session.getState() == VAUProtocolSessionState.closed) {
        session.setState(VAUProtocolSessionState.closed);
        vauProtocol.tryToPersist();
        throw new VAUProtocolException(VAUProtocolException.ACCESS_DENIED);
      }

      TransportedData transportedData = vauProtocol.decrypt(rawRequest);
      message.put("Content-Type", transportedData.contentType);
      String charset = findCharset(transportedData.contentType);
      message.put("org.apache.cxf.message.Message.ENCODING", charset);
      if (this.decryptedHTTPMessageLogger != null)
        this.decryptedHTTPMessageLogger.logMessage(!isOutbound, message, transportedData.body);
      InputStream myInputStream = new ByteArrayInputStream(transportedData.body);
      message.setContent(InputStream.class, myInputStream);
    }
  }

  private boolean isAccessDeniedException(byte[] rawMessageData) {
    try {
      String xml = new String(rawMessageData, Charsets.UTF_8);
      // simplified
      return xml.indexOf(VAUProtocolException.ACCESS_DENIED) != -1;
    } catch (Exception e) {
    }
    return false;
  }

  private boolean isAccessDeniedExceptionByVAU(byte[] rawMessageData) {
    try {
      String xml = new String(rawMessageData, Charsets.UTF_8);
      // simplified
      return xml.indexOf(VAUProtocolException.CONTEXT_MANAGER_ACCESS_DENIED) == -1;
    } catch (Exception e) {
    }
    return false;
  }

  public byte[] readContentFromMessage(Message message) {
    InputStream is = message.getContent(InputStream.class);

    ByteArrayOutputStream bout = new ByteArrayOutputStream();
    try {
      org.apache.cxf.helpers.IOUtils.copy(is, bout);
    } catch (IOException ex) {
      log.error(ex.getMessage(), ex);
    }
    byte[] rawRequest = bout.toByteArray();
    return rawRequest;
  }

  private void handleExceptionInEncryptionLayer(Message message, Exception e) {
    String errorMessage = e.getMessage();
    handleExceptionInEncryptionLayer(message, errorMessage);
  }

  private void handleExceptionInEncryptionLayer(Message message, String errorMessage) {
    VAUProtocol vauProtocol = vauProtocolProvider.getVAUProtocol();
    if (!vauProtocol.session().isClient()) {
      message.getExchange().put("jsonerror", errorMessage);

      final HttpServletResponse httpResponse =
          (HttpServletResponse) message.get(AbstractHTTPDestination.HTTP_RESPONSE);

      log.error("Exception in Encryption Layer");
      throw new RuntimeException(errorMessage);
    } else {
      log.error(errorMessage);
    }
  }

  private void handleVauProtocolError(Message message, String jsonerror) {
    message.put(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON);
    final HttpServletResponse httpResponse =
        (HttpServletResponse) message.get(AbstractHTTPDestination.HTTP_RESPONSE);

    VAUProtocol vauProtocol = vauProtocolProvider.getVAUProtocol();
    VAUProtocolSession session = vauProtocol.session();

    session.setState(VAUProtocolSessionState.closed);
    this.vauProtocolProvider.closeVAUProtocol(vauProtocol);
    vauProtocol.tryToPersist();

    String errorStr = "";
    if (VAUProtocolException.CONTEXT_MANAGER_ACCESS_DENIED.equals(jsonerror)) {
      // Context manager does not produce VAUServerErrorMessage
      errorStr = jsonerror;
    } else {
      errorStr = vauProtocol.generateVAUServerErrorMessage(jsonerror);
    }

    OutputStream os = message.getContent(OutputStream.class);
    CachedStream cs = new CachedStream();
    message.setContent(OutputStream.class, cs);

    message.getInterceptorChain().doIntercept(message);

    try {
      cs.flush();
      CachedOutputStream csnew = (CachedOutputStream) message.getContent(OutputStream.class);

      message.setContent(OutputStream.class, os);
      csnew.getBytes();
      byte[] data_ = errorStr.getBytes(StandardCharsets.UTF_8);
      os.write(data_, 0, data_.length);

      cs.close();
      os.flush();
      os.close();

    } catch (IOException e) {
      log.error(e.getMessage(), e);
    }
  }

  private class CachedStream extends CachedOutputStream {

    public CachedStream() {
      // forces CachedOutputStream to keep the whole content in-memory.
      super(1024 * 1024 * (long) 1024);
    }

    protected void doFlush() throws IOException {
      currentStream.flush();
    }

    protected void doClose() throws IOException {}

    protected void onWrite() throws IOException {}
  }
}
