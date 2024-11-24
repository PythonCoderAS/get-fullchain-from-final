import argparse
import socket

from OpenSSL import crypto
import re
from requests import Session
import sys
from ssl import get_server_certificate

ca_url_pattern = re.compile(r'CA Issuers - URI:(\S+)')

class CertChainBuilder:
    def get_next_cert_url(self, cert_data: bytes):
        is_pem = False
        try:
            cert_data.decode("utf-8")
            is_pem = True
        except UnicodeDecodeError:
            pass
        if is_pem:
            cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_data)
        else:
            cert = crypto.load_certificate(crypto.FILETYPE_ASN1, cert_data)
        self.certs.append(cert)
        for i in range(cert.get_extension_count()):
            ext = cert.get_extension(i)
            if ext.get_short_name() == b"authorityInfoAccess":
                if match := ca_url_pattern.search(str(ext)):
                    return match.group(1)
                return None
        return None

    def __init__(self, verbose: bool):
        self.certs = []
        self.session = Session()
        self.verbose = verbose

    def get_cert_from_url(self, url: str) -> bytes:
        with self.session.get(url) as response:
            return response.content

    @staticmethod
    def get_cert_common_name(cert: crypto.X509) -> str:
        return cert.get_subject().CN


    def feed(self, inital_cert: bytes):
        next_url = self.get_next_cert_url(inital_cert)
        while next_url:
            if self.verbose:
                print(f"Fetching next certificate from {next_url}")
            next_cert = self.get_cert_from_url(next_url)
            next_url = self.get_next_cert_url(next_cert)

    @staticmethod
    def get_cert_pem(cert: crypto.X509) -> str:
        return crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode("utf-8").rstrip("\n")

    def build_chain(self) -> str:
        # Order: Initial, Intermediate Certs, Root
        # Intermediate Certs: Highest -> Lowest (in the context of self.certs, this means from higher indices to lower)
        # Initial: self.certs[0]
        # Root: self.certs[-1]
        assert len(self.certs) >= 2
        chain = [self.get_cert_pem(self.certs[0])]
        for cert in self.certs[-2:0:-1]: # Starts from the second highest index and goes to the second lowest index
            chain.append(self.get_cert_pem(cert))
        chain.append(self.get_cert_pem(self.certs[-1]))
        return "\n".join(chain)

def main(args=None):
    parser = argparse.ArgumentParser(description="Build a certificate chain from a certificate")
    parser.add_argument("cert", help="The certificate to build the chain from (either a file path or a hostname/hostname+port combination, use '-' to read from stdin)")
    parser.add_argument("--out", help="The file to write the chain to (otherwise writes to stdout)")
    parser.add_argument("--verbose", help="Logs intermediate certificate URLs", action="store_true")
    parser.add_argument("--save-intermediate-certificates", help="Saves intermediate certificates", action="store_true")
    args = parser.parse_args(args)
    if args.cert == "-":
        cert_data = sys.stdin.buffer.read()
    else:
        try:
            with open(args.cert, "rb") as f:
                cert_data = f.read()
        except FileNotFoundError:
            # Treat it as a hostname or hostname+port combination
            if "/" in args.cert:
                print("Invalid certificate path: " + args.cert, file=sys.stderr)
                sys.exit(1)
            hostname, sep, port = args.cert.partition(":")
            if not sep:
                port = 443
            else:
                port = int(port)
            try:
                if args.verbose:
                    print(f"Fetching certificate for {hostname}:{port}")
                cert_data = get_server_certificate((hostname, port)).encode("utf-8")
            except socket.gaierror:
                print(f"Could not resolve hostname: {hostname}", file=sys.stderr)
                sys.exit(1)
    builder = CertChainBuilder(verbose=args.verbose)
    builder.feed(cert_data)
    chain = builder.build_chain()
    if args.out:
        with open(args.out, "w") as f:
            f.write(chain)
    else:
        print(chain)
    if args.save_intermediate_certificates:
        for i, cert in enumerate(builder.certs[1:]):
            with open(f"{builder.get_cert_common_name(cert)}.pem", "w") as f:
                f.write(builder.get_cert_pem(cert) + "\n")
    return

if __name__ == "__main__":
    main()
