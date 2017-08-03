#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <pthread.h>
#include <sys/stat.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define CERT_FILE  "a.crt"
#define KEY_FILE   "a.key"

#define CERT_B "did:sov:bbbbb#cert1"


typedef struct did_directory_t {
  const char *name;
  const char *cert_file;
  const char *cert_key;
} did_directory_t;

struct did_directory_t did_directory;



void *load_signer_cert(void *arg)
{
  sleep(1);
  char *cert = (char *)arg;
  struct stat st;

  if (cert == NULL || cert[0] == '\0')
    return NULL;

  if (strcmp(cert, CERT_B)) {
    printf("unknown cert %s\n", cert);
    return NULL;
  }
					    
  if (stat("b.crt", &st) == -1)
    return NULL;

  if (stat("b.key", &st) == -1)
    return NULL;

  did_directory.name = CERT_B;
  did_directory.cert_file = "b.crt";
  did_directory.cert_key  = "b.key";

  printf("loaded new cert\n");
  free(cert);

  pthread_exit(NULL);
}



SSL_CTX *create_context()
{
  const SSL_METHOD *method;
  SSL_CTX *ctx;

  method = TLSv1_2_server_method();
  ctx = SSL_CTX_new(method);
  if (!ctx) {
    printf("Unable to create SSL context");
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
  }

  return ctx;
}



int check_hosted_did(const char *server_did)
{
  if (server_did == NULL || server_did[0] == '\0' || did_directory.name == NULL)
    return -1;

  if (!strcmp(did_directory.name, server_did))
    return 0;

  return -1;
}



int handle_sni(SSL *ssl_socket, int *ad, void *ag)
{
  /* sample SNI format: did:sov:aaaaa#cert1.did:sov:bbbbb#cert1 */

  /* check that SNI hint starts with "did:"
   *    grab server_did and signer_cert_fragment by splitting SNI hint
   *    if we don't have server_did return error
   *    if we don't have the signer_cert_fragment then look it up, return 48
   *    create new context with correct signer_cert_fratment
   *    change socket context to new context
   */

  const char *server_name = NULL;
  char *sni_hint = NULL;
  char *server_did = NULL;
  char *signer_cert_fragment = NULL;

  if (ssl_socket == NULL)
    return SSL_TLSEXT_ERR_NOACK;

  server_name = SSL_get_servername(ssl_socket, TLSEXT_NAMETYPE_host_name);

  if (server_name == NULL || server_name[0] == '\0')
    return SSL_TLSEXT_ERR_NOACK;

  if (strncmp(server_name, "did:", strlen("did:")))
    return SSL_TLSEXT_ERR_OK;

  sni_hint = strdup(server_name);

  server_did = strtok(sni_hint, ".");
  signer_cert_fragment = strdup(strtok(NULL, "."));

  /* check if we already have the certificate */
  if (check_hosted_did(signer_cert_fragment) == -1 || did_directory.name == NULL) {
    /* no cert, load it into cache */
    pthread_t thread;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

    pthread_create(&thread, &attr, &load_signer_cert, signer_cert_fragment);

    pthread_attr_destroy(&attr);

    printf("Hanging up\n");

    free(sni_hint);

    return SSL_TLSEXT_ERR_NOACK;
  }

  free(signer_cert_fragment);
  free(sni_hint);

  /*switch certificates for this context */
  SSL_CTX* ctx = create_context();
  if (ctx == NULL)
    return SSL_TLSEXT_ERR_NOACK;

  if (SSL_CTX_use_certificate_file(ctx, did_directory.cert_file, SSL_FILETYPE_PEM) <= 0) {
    printf("Error setting the certificate file.\n");
    exit(0);
  }

  /*key file to be used*/
  if (SSL_CTX_use_PrivateKey_file(ctx, did_directory.cert_key, SSL_FILETYPE_PEM) <= 0) {
    printf("Error setting the key file.\n");
    exit(0);
  }

  /*ensure key and certificate file*/
  if (SSL_CTX_check_private_key(ctx) == 0) {
    printf("Private key does not match the certificate public key\n");
    exit(0);
  }

  /*client authentication will be used*/
  SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

  /*load certificates of trusted CAs*/
  if (SSL_CTX_load_verify_locations(ctx, did_directory.cert_file, NULL)<1) {
    printf("Error setting the verify locations.\n");
    exit(0);
  }

  /*set CA list used for client authentication. */
  SSL_CTX_set_client_CA_list(ctx, SSL_load_client_CA_file(did_directory.cert_file));

  SSL_CTX* v = SSL_set_SSL_CTX(ssl_socket, ctx);
  if (v != ctx)   
    return SSL_TLSEXT_ERR_NOACK;

  printf("Changing context\n");

  return SSL_TLSEXT_ERR_OK;
}



int create_socket()
{
  int listener_socket;
  struct sockaddr_in addr;

  addr.sin_family = AF_INET;
  addr.sin_port = htons(8443);
  addr.sin_addr.s_addr = htonl(INADDR_ANY);

  listener_socket = socket(AF_INET, SOCK_STREAM, 0);
  if (listener_socket < 0) {
    printf("Unable to create socket");
    exit(EXIT_FAILURE);
  }

  if (bind(listener_socket, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
    printf("Unable to bind");
    exit(EXIT_FAILURE);
  }

  if (listen(listener_socket, 1) < 0) {
    printf("Unable to listen");
    exit(EXIT_FAILURE);
  }

  return(listener_socket);
}


int main(int argc, char *argv[])
{
  int error, count;
  char buff[32];

  const SSL_METHOD *meth;
  int connection_socket;
  SSL_CTX  *ctx;
  SSL  *ssl;

  SSL_library_init();

  ctx = create_context();

  /*certificate to be used.*/
  if (SSL_CTX_use_certificate_file(ctx, CERT_FILE, SSL_FILETYPE_PEM) <= 0) {
    printf("Error setting the certificate file.\n");
    exit(0);
  }

  /*key file to be used*/
  if (SSL_CTX_use_PrivateKey_file(ctx, KEY_FILE, SSL_FILETYPE_PEM) <= 0) {
    printf("Error setting the key file.\n");
    exit(0);
  }

  /*ensure key and certificate match*/
  if (SSL_CTX_check_private_key(ctx) == 0) {
    printf("Private key does not match the certificate public key\n");
    exit(0);
  }

  /*client authentication will be used*/
  SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

  /*load certificates of trusted CAs*/
  if (SSL_CTX_load_verify_locations(ctx, CERT_FILE, NULL)<1) {
    printf("Error setting the verify locations.\n");
    exit(0);
  }

  /*set CA list used for client authentication. */
  SSL_CTX_set_client_CA_list(ctx, SSL_load_client_CA_file(NULL));
  SSL_CTX_set_tlsext_servername_callback(ctx, handle_sni);

  connection_socket = create_socket();

  while (1) {
    struct sockaddr_in addr;
    uint len = sizeof(addr);
    int listener_socket = accept(connection_socket, (struct sockaddr*)&addr, &len);
    if (listener_socket < 0) {
      printf("Unable to accept");
      exit(EXIT_FAILURE);
    }
  
    ssl = SSL_new(ctx);
  
    if (!ssl) {
      printf("Error creating SSL structure.\n");
      exit(0);
    }
  
    SSL_set_fd(ssl, listener_socket);
  
    error = SSL_accept(ssl);
  
    if (error < 1) {
      error = SSL_get_error(ssl, error);
      printf("SSL error #%d in SSL_accept\n", error);
      if (error == 5){printf("socket error\n");}
        continue;
    }
  
    if (SSL_get_verify_result(ssl) != X509_V_OK) {
        printf("SSL Client Authentication error\n");
        SSL_free(ssl);
        continue;
    }
  
    printf("SSL connection on socket %x, Version: %s, Cipher: %s\n",
    connection_socket,
    SSL_get_version(ssl),
    SSL_get_cipher(ssl));
  
    error = SSL_read (ssl, buff, sizeof(buff));
  
    if (error < 1) {
      error = SSL_get_error(ssl, error);
      printf("Error #%d in read\n", error);
  
      if (error == 6)
        SSL_shutdown(ssl);
  
      SSL_free(ssl);
      continue;
    }
    printf("Client said: %s\n", buff);
  
    error = SSL_write(ssl, "Hello from server.", sizeof("Hello from server.")+1);
  
    if (error < 1) {
      error = SSL_get_error(ssl, error);
      printf("Error #%d in write\n", error);
  
      SSL_free(ssl);
      continue;
    }

  error = SSL_shutdown(ssl);
  break;
  }

  count = 1;

  while(error != 1) {
    error=SSL_shutdown(ssl);
    if (error != 1)
      count++;
    if (count == 5)
      break;
    sleep(1);
  }

  printf("server exiting\n");

  SSL_free(ssl);
  close(connection_socket);
  SSL_CTX_free(ctx);
  exit(0);
}

