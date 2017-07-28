import aiohttp
import asyncio
import ssl
import socket
aiodns_default = True

ssl_ctx = ssl.create_default_context(purpose=ssl.Purpose.CLIENT_AUTH)
ssl_ctx.load_cert_chain(certfile='certs/b.crt', keyfile='certs/b.key')
ssl_ctx.check_hostname = False
#ssl_ctx.verify_mode = ssl.CERT_NONE


async def main():

    signer_did_cert_fragment = "did:sov:bbbbb#cert1"

    remote_did = "did:sov:aaaaa#cert1"
    #TODO: Look up fingerprint and host from DID.
    remote_fingerprint = b'\x05F\xdd\x86\x1d\xba;\\E\x19R\xdf\xbf\xc4\x95H\xe03\xa7\xe4\xfe(\n\x86\x9f\xd1\xaf2\xf5\x9c\xf4w'
    remote_agent_host = 'https://localhost:8443/'

    sni_package = ".".join([remote_did, signer_did_cert_fragment])

    print("SNI Package Length: {}".format(len(sni_package)))


    # Prepare SNI Resolver
    class CustomSNIResolver(aiohttp.resolver.DefaultResolver):
        @asyncio.coroutine
        def resolve(self, host, port=0, family=socket.AF_INET):
            hosts = yield from super().resolve(host, port, family)
            for h in hosts:
                h['hostname'] = sni_package # this is used as the sni hint
            return hosts

    conn = aiohttp.TCPConnector(resolver=CustomSNIResolver(), fingerprint=remote_fingerprint, ssl_context=ssl_ctx) #verify_ssl=False

    #make request
    async with aiohttp.ClientSession(connector=conn) as session:
        remaining_retries = 3
        while remaining_retries > 0:
            remaining_retries -= 1
            try:
                async with session.get(remote_agent_host) as response:
                    print( await response.text())
                    break #request success
            except aiohttp.ServerFingerprintMismatch as e:
                exc = e
                print("Remote Cert Fingerprint Not Matching: ")
                print(exc.expected)
                break
            except aiohttp.client_exceptions.ClientConnectorError as ce:
                print("sleeping, waiting for a retry")
                await asyncio.sleep(2)


loop = asyncio.get_event_loop()
loop.run_until_complete(main())