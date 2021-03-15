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
package de.gematik.ti.vauchannel.cxf;

import de.gematik.ti.vauchannel.protocol.VAUProtocol;
import java.security.cert.X509Certificate;

public interface VAUProtocolProvider {
  boolean isClient();

  VAUProtocol getVAUProtocol();

  VAUProtocol getVAUProtocolByKeyID(byte[] keyID); // on server

  VAUProtocol getVAUProtocol(X509Certificate cert); // on server

  VAUProtocol getVAUProtocol(String someIdentifier);

  void closeVAUProtocol(VAUProtocol vauProtocol);
}
