import asyncio
from aiohttp import web
import ssl
import os

routing_key = "did:sov:rrrrr#routingcert"

#command used to generate certs:
# openssl req -newkey rsa:2048 -nodes -keyout x.key -x509 -days 365 -out x.crt
certfile = os.path.abspath("certs/a.crt")
private_certfile = os.path.abspath("certs/a.key")

hosted_did_directory = {
    'did:sov:aaaaa#cert1': {'cert':'certs/a.crt', 'key':'certs/a.key'}
}

signer_cert_cache = {}

async def load_signer_cert(did_cert_fragment):
    await asyncio.sleep(0.5) #pretend to be async
    if did_cert_fragment == 'did:sov:bbbbb#cert1':
        with open('certs/b.crt') as f:
            signer_cert_cache['did:sov:bbbbb#cert1'] = f.read()
        print("cert loaded")
    else:
        print("requested cert fragment unknown. cannot load to cache")

def decode_sni_payload(payload, routing_key):
    # TODO: Decrypt Payload with routing_key
    remote_did, local_did, signer_did = payload.split(".")
    return remote_did, local_did, signer_did

def validate_client_cert(request):
    ssl_socket = request.transport.get_extra_info('ssl_object')
    peer_cert_raw = ssl_socket.getpeercert(binary_form=True)
    peer_cert_details = ssl_socket.getpeercert()
    peer_cert_subject = {t[0][0]:t[0][1] for t in list(peer_cert_details['subject'])}
    client_did = peer_cert_subject['commonName']
    print("Peer Cert: ")
    print(client_did)
    print(peer_cert_raw)
    # TODO: verify certificate is presented as expected.

async def client_cert_middleware(app, handler):
    async def middleware_handler(request):
        validate_client_cert(request)
        # TODO: Fail request if client cert is not valid.
        # TODO: Augment request context with client cert information.

        return await handler(request)
    return middleware_handler

async def hello(request):
    #mutual auth in place.
    return web.Response(body=b'hello')

app = web.Application(middlewares=[client_cert_middleware])
app.router.add_route('GET', '/', hello)


def handle_sni(ssl_socket, sni_hint, orig_ssl_context):
    print("Processing SNI: " + sni_hint)
    # This is the DID that the client is expecting to talk to.
    if sni_hint.startswith("did:"):
        #unpack sni hint
        server_did, client_did, signer_cert_fragment = decode_sni_payload(sni_hint, routing_key)

        if server_did in hosted_did_directory:
            did_cert = hosted_did_directory[server_did]

            if signer_cert_fragment not in signer_cert_cache:
                print("Signer Cert not in cache. Load async.")
                app.loop.create_task(load_signer_cert(signer_cert_fragment))
                print("Hangup")
                return 46
            # 48 certificate_unknown

            signer_cert = signer_cert_cache[signer_cert_fragment]

            new_context = ssl.create_default_context(purpose=ssl.Purpose.CLIENT_AUTH, cadata=signer_cert)#cafile='certs/b.crt'
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