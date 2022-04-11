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

import static de.gematik.ti.vauchannel.protocol.helpers.ObjectMapperFactory.objectMapper;

import com.fasterxml.jackson.databind.ObjectMapper;
import de.gematik.rs.vau.VAUServerErrorData;
import org.junit.Assert;
import org.junit.Test;

public class DateTimeFormatTest {

  @Test
  public void testDateTimeFormat() throws Exception {

    ObjectMapper mapper = objectMapper();

    // deserializing
    String str1 = "{\"Time\":\"2020-10-16T09:28:04.304Z\"}";
    VAUServerErrorData d1 = mapper.readValue(str1, VAUServerErrorData.class);

    String str2 = "{\"Time\":\"2018-11-22T10:00:00.123456\"}";
    VAUServerErrorData d2 = mapper.readValue(str2, VAUServerErrorData.class);

    String str2b = mapper.writeValueAsString(d2);
    Assert.assertEquals("Serializing format should follow example in specification", str2, str2b);

    String str3 =
        "{\"DataType\":\"VAUServerErrorData\",\"Data\":\"Dies ist ein VauServerError!\",\"Time\":\"2020-10-06T10:02:15.441301\"}";
    VAUServerErrorData d3 = mapper.readValue(str3, VAUServerErrorData.class);
  }
}
