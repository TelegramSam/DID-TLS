import asyncio
from aiohttp import web
import ssl
import os

#command used to generate certs:
# openssl req -newkey rsa:2048 -nodes -keyout x.key -x509 -days 365 -out x.crt
certfile = os.path.abspath("certs/a.crt")
private_certfile = os.path.abspath("certs/a.key")

hosted_did_directory = {
    'did:sov:aaaaa#cert1': {'cert':'certs/a.crt', 'key':'certs/a.key'}
}


async def hello(request):
    ssl_socket = request.transport.get_extra_info('ssl_object')
    peer_cert_raw = ssl_socket.getpeercert(binary_form=True)
    peer_cert_details = ssl_socket.getpeercert()
    peer_cert_subject = {t[0][0]:t[0][1] for t in list(peer_cert_details['subject'])}
    client_did = peer_cert_subject['commonName']
    print("Peer Cert: ")
    print(client_did)
    print(peer_cert_raw)
    #TODO: Look up DID in commonName and verify certificate is presented as expected.

    #mutual auth in place.
    return web.Response(body=b'hello')

app = web.Application()
app.router.add_route('GET', '/', hello)


def handle_sni(ssl_socket, sni_hint, orig_ssl_context):
    print("Processing SNI: " + sni_hint)
    # This is the DID that the client is expecting to talk to.
    if sni_hint.startswith("did:"):
        #unpack sni hint
        server_did, client_signed_cert = sni_hint.split(".")

        if server_did in hosted_did_directory:
            did_cert = hosted_did_directory[server_did]
            with open('certs/b.crt') as f:
                client_ca_data = f.read()
                client_signed_cert = client_ca_data

            new_context = ssl.create_default_context(purpose=ssl.Purpose.CLIENT_AUTH, cadata=client_signed_cert)#cafile='certs/b.crt'
            new_context.load_cert_chain(certfile=did_cert['cert'], keyfile=did_cert['key'])
            new_context.verify_mode = ssl.CERT_OPTIONAL
            ssl_socket.context = new_context
        else:
            print("Unknown DID requested")
    else:
        print("No DID in SNI hint")

    # requests that do not contain an SNI hint, contain a regular domain, or request a DID
    # not hosted by this server will receive the default certificate.
ssl_context = ssl._create_unverified_context()
#ssl_context = ssl.SSLContext() #ssl.create_default_context(purpose=ssl.Purpose.CLIENT_AUTH)
# default cert will be used in the case of missing DID in SNI
ssl_context.load_cert_chain(certfile="certs/default.crt", keyfile="certs/default.key")
ssl_context.verify_mode = ssl.CERT_OPTIONAL #this prompts send of cert, but we need to disable cert verification

#ssl_context.check_hostname = False
ssl_context.set_servername_callback(handle_sni)


web.run_app(app, ssl_context=ssl_context, port=8443)


# tips about client ssl context, including fingerprint verification:
#  http://aiohttp.readthedocs.io/en/stable/client.html#ssl-control-for-tcp-sockets