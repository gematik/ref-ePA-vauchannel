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

import javax.jws.WebService;

public class ServiceHelper {
    public static ServiceInfo info(Object service) {
        ServiceInfo result = new ServiceInfo();
        WebService annotation = service.getClass().getAnnotation(WebService.class);
        result.name = annotation.name();
//        result.version = service.getClass().getAnnotation(Version.class).value();
        //       result.targetNamespace = annotation.targetNamespace();

        return result;
    }

    public static class ServiceInfo {
        private String name;


        public String name() {
            return name;
        }

        public String path() {
            return name;
        }
    }
}
