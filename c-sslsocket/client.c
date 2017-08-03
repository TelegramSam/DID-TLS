/* https://www.ibm.com/support/knowledgecenter/en/SSB23S_1.1.0.12/gtps7/s5sple2.html */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define CERT_FILE "b.crt"
#define KEY_FILE  "b.key"



int create_socket()
{
  int s;
  struct hostent *host;
  struct sockaddr_in socketaddr;
  
  if ((host = gethostbyname("localhost")) == NULL) {
     printf("could not determine hostname");
     exit(EXIT_FAILURE);
  }
  
  s = socket(PF_INET, SOCK_STREAM, 0);
  bzero(&socketaddr, sizeof(socketaddr));
  socketaddr.sin_family = AF_INET;
  socketaddr.sin_port = htons(8443);
  socketaddr.sin_addr.s_addr = *(long*)(host->h_addr);
 
  if (connect(s, (struct sockaddr*)&socketaddr, sizeof(socketaddr)) != 0) {
    printf("Socket returned error, program terminated\n");
    exit(EXIT_FAILURE);
  }
 
  return(s);
}


SSL_CTX *create_context()
{
  const SSL_METHOD *meth;
  meth=TLSv1_2_client_method();
  SSL_CTX *ctx;
  
  ctx=SSL_CTX_new(meth);
  if (!ctx) {
     printf("Error creating the context.\n");
     exit(0);
  }
  
  /*certificate file to be used*/
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
  
  /* Set the list of trusted CAs*/
  if (SSL_CTX_load_verify_locations(ctx, CERT_FILE, NULL)<1) {
     printf("Error setting verify location\n");
     exit(0);
  }
  
  /* Set for server verification*/
  SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

  return(ctx);
}


int main(int argc, char *argv[])
{
  int socket;
  int error, count;
  char buff[32];
  char sni_hint[64];
  int rc;
  
  /*SSL PART*/
  SSL_CTX *ctx;
  SSL *ssl;
  
 
  /* SSL Part*/
  SSL_library_init();
  SSL_load_error_strings();
  
  snprintf(sni_hint, sizeof(sni_hint), "did:sov:aaaaa#cert1.did:sov:bbbbb#cert1");
  
  do {
    sleep(1);
    rc = -1;

    ctx=create_context();
    ssl=SSL_new(ctx);
    socket = create_socket();
    
    if (!ssl) {
       printf("Error creating SSL structure.\n");
       exit(EXIT_FAILURE);
       continue;
    }

    SSL_set_tlsext_host_name(ssl, sni_hint);
   
    SSL_set_fd(ssl, socket);
    
    error = SSL_connect(ssl);
    
    if (error < 1) {
       error = SSL_get_error(ssl, error);

       printf("SSL error #%d in accept\n", error);
    
       SSL_free(ssl);
       SSL_CTX_free(ctx);
       continue;
    }
    
    printf("SSL connection on socket %x, Version: %s, Cipher: %s\n",
  	 socket,
  	 SSL_get_version(ssl),
  	 SSL_get_cipher(ssl));
    
    /*send message to the server*/
    error = SSL_write(ssl, "Hello from client.", sizeof("Hello from client.")+1);

    if (error < 1) {
       error = SSL_get_error(ssl, error);
       printf("Error #%d in write\n", error);

       SSL_free(ssl);
       SSL_CTX_free(ctx);
       continue;
    }
    

    error = SSL_read (ssl, buff, sizeof(buff));

    if (error < 1) {
       error = SSL_get_error(ssl, error);
       printf("Error #%d in read\n", error);

       if (error == 6)
         SSL_shutdown(ssl);

        SSL_free(ssl);
        SSL_CTX_free(ctx);
        continue;
    }

    rc = 1;
  } while (rc <= 0);
  
  printf("Server said: %s\n", buff);
  
  error = SSL_shutdown(ssl);
  count = 1;
  
  while(error != 1) {
     error = SSL_shutdown(ssl);
     if (error != 1)
       count++;
     if (count == 5)
       break;
     sleep(1);
  }
  
  printf("client exiting\n");
  
  close(socket);
  SSL_free(ssl);
  SSL_CTX_free(ctx);
  exit(0);
}
