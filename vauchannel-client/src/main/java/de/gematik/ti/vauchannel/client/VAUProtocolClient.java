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
package de.gematik.ti.vauchannel.client;


import com.fasterxml.jackson.jaxrs.json.JacksonJsonProvider;
import de.gematik.ti.vauchannel.cxf.*;
import org.apache.cxf.jaxrs.client.JAXRSClientFactory;
import org.apache.cxf.jaxws.JaxWsProxyFactoryBean;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;

import java.util.Collections;

import static javax.xml.ws.soap.SOAPBinding.SOAP12HTTP_BINDING;


@ComponentScan(basePackages = "de.gematik.ti.*")
@SpringBootApplication(scanBasePackages = {"de.gematik.ti.*"})
public class VAUProtocolClient implements CommandLineRunner {
    private final Logger logger = LoggerFactory.getLogger(this.getClass());


    private String serverAddress = "localhost";
    private String serverPort = "9094";

    public static void main(String[] args) {
        SpringApplication.run(VAUProtocolClient.class, args);
    }


    @Bean()
    public AESOutInterceptor aESOutInterceptor() {
        return new AESOutInterceptor();
    }

    @Bean()
    public AESInInterceptor aESInInterceptor() {
        return new AESInInterceptor();
    }

    @Bean()
    public SomeServiceInterface someService() {
        JaxWsProxyFactoryBean jaxWsProxyFactory = new JaxWsProxyFactoryBean();
        jaxWsProxyFactory.setServiceClass(SomeServiceInterface.class);
        jaxWsProxyFactory.setBindingId(SOAP12HTTP_BINDING);
        jaxWsProxyFactory.setAddress("http://" + serverAddress + ":" + serverPort + "/services");

        jaxWsProxyFactory.getOutInterceptors().add(aESOutInterceptor());
        jaxWsProxyFactory.getInInterceptors().add(aESInInterceptor());

        SomeServiceInterface pt = (SomeServiceInterface) jaxWsProxyFactory.create();

        return pt;
    }

    @Bean()
    public HandshakeRSJsonInterface handshakeServer() {
        return JAXRSClientFactory.create("http://" + serverAddress + ":" + serverPort + "/services/handshake", HandshakeRSJsonInterface.class, Collections.singletonList(new JacksonJsonProvider()));
    }

    @Override
    public void run(String... args) throws Exception {

    }

}
