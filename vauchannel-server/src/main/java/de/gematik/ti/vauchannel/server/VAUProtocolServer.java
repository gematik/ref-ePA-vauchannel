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
package de.gematik.ti.vauchannel.server;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.jaxrs.json.JacksonJaxbJsonProvider;
import de.gematik.ti.vauchannel.cxf.AESInInterceptor;
import de.gematik.ti.vauchannel.cxf.AESOutFaultStatusCodeInterceptor;
import de.gematik.ti.vauchannel.cxf.AESOutInterceptor;
import de.gematik.ti.vauchannel.cxf.SomeServiceInterface;
import org.apache.cxf.bus.spring.SpringBus;
import org.apache.cxf.endpoint.Server;
import org.apache.cxf.feature.LoggingFeature;
import org.apache.cxf.jaxrs.JAXRSServerFactoryBean;
import org.apache.cxf.jaxws.EndpointImpl;
import org.apache.cxf.validation.BeanValidationFeature;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

import javax.xml.ws.Endpoint;
import javax.xml.ws.soap.SOAPBinding;
import java.security.Security;
import java.util.Arrays;

import static de.gematik.ti.vauchannel.protocol.helpers.ObjectMapperFactory.objectMapper;

@SpringBootApplication(scanBasePackages = {"de.gematik.ti.*"})
public class VAUProtocolServer {
    private final Logger logger = LoggerFactory.getLogger(this.getClass());
    @Autowired
    private SpringBus bus;

    public static void main(String[] args) {
        Security.addProvider(new BouncyCastleProvider());
        SpringApplication.run(VAUProtocolServer.class, args);
    }

    @Bean
    public SomeServiceInterface someService() {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        return new SomeService();
    }

    @Bean
    public Endpoint someServiceEndpoint() {
        return publishService(someService());
    }

    @Bean()
    public AESOutInterceptor aESOutInterceptor() {
        return new AESOutInterceptor();
    }

    @Bean()
    public AESInInterceptor aESInInterceptor() {
        return new AESInInterceptor();
    }

    private Endpoint publishService(Object service) {
        ServiceHelper.ServiceInfo serviceInfo = ServiceHelper.info(service);

        EndpointImpl endpoint = new EndpointImpl(bus, service, SOAPBinding.SOAP12HTTP_BINDING);

        endpoint.getOutInterceptors().add(aESOutInterceptor());
        endpoint.getOutFaultInterceptors().add(aESOutInterceptor());
        endpoint.getOutFaultInterceptors().add(new AESOutFaultStatusCodeInterceptor());
        endpoint.getFeatures().add(beanValidationFeature());

        endpoint.getInInterceptors().add(aESInInterceptor());

        endpoint.publish("/" + serviceInfo.path());

        return endpoint;
    }


    @Bean
    public BeanValidationFeature beanValidationFeature() {
        return new BeanValidationFeature();
    }


    @Bean
    public LoggingFeature loggingFeature() {
        LoggingFeature logFeature = new LoggingFeature();
        logFeature.setPrettyLogging(true);
        logFeature.initialize(bus);
        return logFeature;
    }

    @Bean
    public JacksonJaxbJsonProvider jsonProvider(ObjectMapper objectMapper) {
        JacksonJaxbJsonProvider provider = new JacksonJaxbJsonProvider();
        provider.setMapper(objectMapper);
        return provider;
    }

    @Bean
    public HandshakeRSJson handshakeRSJson() {
        return new HandshakeRSJson();
    }

    @Bean
    public Server rsServer() {

        JAXRSServerFactoryBean endpoint = new JAXRSServerFactoryBean();
        endpoint.setBus(bus);
        endpoint.setAddress("/handshake");
        endpoint.setServiceBeans(Arrays.asList(handshakeRSJson()));
        endpoint.setProvider(jsonProvider(objectMapper()));

        endpoint.setFeatures(Arrays.asList(loggingFeature()));

        return endpoint.create();
    }


}
