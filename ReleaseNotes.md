# Release 1.3.7
Die Generierung der OCSPResponse wurde gemäß Anforderung GS-A_4693-01 [gemSpec_PKI] um die OCSP-Extension "certHash" erweitert. \
Außerdem wird nun in der OCSP-Response gemäß RFC6960 folgendes sichergestellt:
- Das Feld CertID wird mit den Informationen des CA-Zertifikates befüllt
- Die ResponderID wird basierend auf dem Key des OCSP-Signers berechnet
- Das öffentliche Zertifikat des OCSP-Signers wird in der Response mitgeliefert

