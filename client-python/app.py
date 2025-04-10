import ssl
from dataclasses import dataclass

import requests
from requests.adapters import HTTPAdapter
from urllib3.poolmanager import PoolManager


class TLSAdapter(HTTPAdapter):
    def __init__(self, ssl_context, server_hostname):
        self.ssl_context = ssl_context
        self.server_hostname = server_hostname
        super().__init__()

    def init_poolmanager(self, *args, **kwargs):
        kwargs["ssl_context"] = self.ssl_context
        kwargs["server_hostname"] = self.server_hostname
        self.poolmanager = PoolManager(*args, **kwargs)


def create_standard_client(ca_path, server_name):
    ctx = ssl.create_default_context(cafile=ca_path)
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    return TLSAdapter(ctx, server_name)


@dataclass
class ClientConf:
    name: str
    addr: str
    server_name: str
    expected_ok: bool


def test_request(conf, session):
    url = f"https://localhost{conf.addr}"
    try:
        resp = session.get(url, timeout=5)
        body = resp.text
        if conf.expected_ok:
            print(
                "  \033[32m✔\033[0m ",
                f"Request to {conf.addr} (as {conf.server_name}) succeeded",
            )
            print("    - Response:", body)
        else:
            print(
                "  \033[31m✘\033[0m ",
                f"Request to {conf.addr} (as {conf.server_name}) succeeded but was not expected to",
            )
    except Exception as e:
        if conf.expected_ok:
            print(
                "  \033[31m✘\033[0m ",
                f"Request to {conf.addr} (as {conf.server_name}) failed: {e}",
            )
        else:
            print(
                "  \033[32m✔\033[0m ",
                f"Request to {conf.addr} (as {conf.server_name}) failed as expected: {e}",
            )


def main():
    ca_path = "ca/root/root.cert.pem"

    configs = [
        ClientConf(
            "domain_correct_ou_correct",
            ":8443",
            "only-this-domain-is-allowed.com",
            True,
        ),
        ClientConf(
            "domain_incorrect_ou_correct",
            ":8444",
            "only-this-domain-is-allowed.com",
            False,
        ),
        ClientConf(
            "domain_correct_ou_incorrect",
            ":8445",
            "this-domain-is-not-allowed.com",
            False,
        ),
        ClientConf(
            "domain_incorrect_ou_incorrect",
            ":8446",
            "this-domain-is-not-allowed.com",
            False,
        ),
    ]

    print("\nTesting using the standard TLS client")
    print("=====================================\n")

    for conf in configs:
        print(f"Testing {conf.name}")
        session = requests.Session()
        adapter = create_standard_client(ca_path, conf.server_name)
        session.mount("https://", adapter)
        test_request(conf, session)
        print()


if __name__ == "__main__":
    main()

