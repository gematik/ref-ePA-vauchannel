package de.gematik.ti.vauchannel.protocol.helpers;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.module.SimpleModule;
import java.time.LocalDateTime;

public class ObjectMapperFactory {
  public static ObjectMapper objectMapper() {
    ObjectMapper mapper = new ObjectMapper();
    mapper.disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
    SimpleModule dateModule = new SimpleModule();
    dateModule.addSerializer(new CustomISO8601LocalDateTimeSerializer());
    dateModule.addDeserializer(LocalDateTime.class, new CustomISO8601LocalDateTimeDeserializer());
    mapper.registerModule(dateModule);
    return mapper;
  }
}
