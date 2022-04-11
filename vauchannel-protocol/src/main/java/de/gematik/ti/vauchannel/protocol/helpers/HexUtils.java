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

import java.math.BigInteger;
import javax.xml.bind.DatatypeConverter;
import org.apache.commons.lang3.ArrayUtils;

public class HexUtils {
  public static String convertToLowerCaseHexWith64ByteLength(BigInteger value) {
    return convertToLowerCaseHexWith64ByteLength(value.toByteArray());
  }

  public static String convertToLowerCaseHexWith64ByteLength(byte[] rawBytes) {
    final byte[] byteArrayWithLimitedLength =
        ArrayUtils.subarray(rawBytes, rawBytes.length - 32, rawBytes.length);

    return DatatypeConverter.printHexBinary(byteArrayWithLimitedLength).toLowerCase();
  }
}
