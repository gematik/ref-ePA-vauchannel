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

import java.nio.charset.StandardCharsets;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Base64 {

  private static final Logger logger = LoggerFactory.getLogger(Base64.class);

  public static byte[] encode(byte[] in) {
    return java.util.Base64.getEncoder().encode(in);
  }

  public static byte[] encode(String in) {
    return encode(in.getBytes(StandardCharsets.UTF_8));
  }

  public static byte[] decode(String in) {
    return java.util.Base64.getDecoder().decode(in.getBytes(StandardCharsets.UTF_8));
  }

  public static String encode2String(byte[] in) {
    return new String(encode(in), StandardCharsets.UTF_8);
  }
}
