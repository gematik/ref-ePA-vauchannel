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
package de.gematik.ti.vauchannel.protocol;

public enum VAUProtocolSessionState {
  handshaking, // vom Erzeugen bis zum vollständigen Abschließen des Handshakes
  open, // nach erfolgreichem Handshake, in der Verschlüsselungsphase
  closing, // auf dem Server, wenn nur noch die Response rausgeschickt werden soll, und dann der
  // Kanal geschlossen ist
  closed // Kanal ist geschlossen und darf nicht mehr verwendet werden
}
