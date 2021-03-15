package de.gematik.ti.vauchannel.protocol.helpers;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import java.io.IOException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

public class CustomISO8601LocalDateTimeDeserializer extends JsonDeserializer<LocalDateTime> {

  /**
   * The ISO-like date-time formatter that formats or parses a date-time with the offset and zone if
   * available, such as '2011-12-03T10:15:30', '2011-12-03T10:15:30+01:00' or
   * '2011-12-03T10:15:30+01:00[Europe/Paris]'. (see javadocs for
   * java/time/format/DateTimeFormatter)
   */
  @Override
  public LocalDateTime deserialize(JsonParser jsonparser, DeserializationContext context)
      throws IOException, JsonProcessingException {
    try {
      return LocalDateTime.parse(jsonparser.getText(), DateTimeFormatter.ISO_DATE_TIME);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }
}
