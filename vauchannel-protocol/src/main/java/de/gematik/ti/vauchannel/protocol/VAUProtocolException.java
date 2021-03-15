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

public class VAUProtocolException extends RuntimeException {
  public static final String ACCESS_DENIED = "Access Denied";
  public static final String CONTEXT_MANAGER = "context manager";
  public static final String CONTEXT_MANAGER_ACCESS_DENIED = CONTEXT_MANAGER + ": " + ACCESS_DENIED;
  public static final String AES_DECRYPTION_ERROR = "AES-GCM decryption error.";
  public static final String INVALID_COUNTER_VALUE = "invalid counter value";
  public static final String MESSAGE_COUNTER_OVERFLOW = "message counter overflow";
  public static final String ENCRYPTION_NOT_SUCCESSFUL = "encryption not successful";
  public static final String INTERNAL_SERVER_ERROR = "internal server error";
  public static final String SERVER_ERROR_SIGNATURE_NOT_VALID = "server error signature not valid";
  public static final String EXCEPTION_PARSING_SERVER_ERROR = "exception parsing server error";
  public static final String ERROR_FORCED_BY_CONFIGURATION =
      "error has been forced by configuration";
  public static final String INVALID_CURVE_ECDH = "invalid curve (ECDH)";
  public static final String SYNTAX_ERROR = "message syntax not correct";
  public static final String UNEXPECTED_VAU_CLIENT_HELLLO_DATA_HASH_ERROR =
      "unexpected VAUClientHelloDataHash";
  public static final String UNEXPECTED_CERTIFICATE_HASH_ERROR = "unexpected Certificate Hash";

  public VAUProtocolException(String s) {
    super(s);
  }

  public VAUProtocolException(String s, Exception e) {
    super(s, e);
  }
}
