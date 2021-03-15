package de.gematik.ti.vauchannel.protocol.helpers;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;
import java.io.IOException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

public class CustomISO8601LocalDateTimeSerializer extends JsonSerializer<LocalDateTime> {

  private DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSSSSS");

  @Override
  public void serialize(
      LocalDateTime date, JsonGenerator jsonGenerator, SerializerProvider serializerProvider)
      throws IOException {
    jsonGenerator.writeString(formatter.format(date));
  }

  public Class<LocalDateTime> handledType() {
    return LocalDateTime.class;
  }
}
