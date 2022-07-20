from datetime import datetime
from typing import Optional

from ocspbuilder import OCSPResponseBuilder
from ocspresponder import OCSPResponder, CertificateStatus

# import monkeypatch
from _pytest.monkeypatch import MonkeyPatch

OCSPResponseBuilder.build = MonkeyPatch.build
OCSPResponder.serve = MonkeyPatch.serve

ISSUER_CERT = 'conf/issuer.crt'
OCSP_CERT = 'conf/cert.pem'
OCSP_KEY = 'conf/key.pem'


class CustomOCSPResponder(OCSPResponder):
    def _route(self):
        self._app.get('/', callback=self._handle_root)
        self._app.get('/status/<request_data>', callback=self._handle_get)
        self._app.post('/status/', callback=self._handle_post)
        self._app.post('/status', callback=self._handle_post)


def validate(serial: int) -> (CertificateStatus, Optional[datetime]):
    return (CertificateStatus.good, None)


def get_cert(serial: int) -> str:
    """
    Assume the certificates are stored in the ``certs`` directory with the
    serial as base filename.
    """
    with open('certs/%s.cert.pem' % serial, 'r') as f:
        return f.read().strip()


app = CustomOCSPResponder(
    ISSUER_CERT, OCSP_CERT, OCSP_KEY,
    validate_func=validate,
    cert_retrieve_func=get_cert,
)

if __name__ == "__main__":
    app.serve(port=8080, debug=True)