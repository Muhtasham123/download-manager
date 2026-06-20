#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include<netdb.h>
#include<stdbool.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include<unistd.h>

void send_request(
    char* path, 
    char* domain, 
    int path_size, 
    int domain_size, 
    char* session_id, 
    int session_id_size,
    char* session_id_key, 
    struct in_addr **addr_list,
    SSL_CTX **ctx,
    SSL **ssl,
    int *sockfd){

    struct sockaddr_in server_address;

    *ctx = SSL_CTX_new(TLS_client_method());
    *ssl = SSL_new(*ctx);

    *sockfd = socket(AF_INET, SOCK_STREAM, 0);
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(443);
    server_address.sin_addr = *addr_list[0];

    if (connect(*sockfd, (struct sockaddr*)&server_address, sizeof(server_address)) < 0){
        printf("Failed to create TCP connection\n\n");
        exit(1);
    }

    SSL_set_fd(*ssl, *sockfd);
    SSL_set_tlsext_host_name(*ssl, domain);
    

    if(SSL_connect(*ssl) <= 0){
        printf("Handshake failed\n\n");
        exit(1);
    }// TLS handshake

    char *http_request = malloc(path_size + domain_size + 50 + session_id_size);

    if(session_id == NULL){
        sprintf(http_request, "GET %s HTTP/1.1\r\nHost: %s\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n", path, domain);
    }
    else{
       sprintf(http_request, "GET %s HTTP/1.1\r\nHost: %s\r\nContent-Type: text/plain\r\nCookie: %s=%s\r\nConnection: close\r\n\r\n", path, domain, session_id_key, session_id); 
    }

    SSL_write(*ssl, http_request, strlen(http_request));
}

void get_response(char *response, int response_size, char** body, char* status_code, SSL *ssl){
    int total = 0;
    int n_bytes;

    printf("\nDownloading...\n");
    while ((n_bytes = SSL_read(ssl, response + total, response_size - total - 1)) > 0)
    {
        total += n_bytes;
    }//reading response

    response[total] = '\0';

    *body = strstr(response, "\r\n\r\n"); //splitting response and body

    if(*body)
    {
        **body = '\0';
        *body += 4;
    }

    //getting status code
    for(int i = 0; i<3; i++){
        status_code[i] = response[9 + i]; //because status code in header starts at 9th index;
    }
    status_code[3] = '\0';
    printf("Status code : %s\n", status_code);
}

int main(){
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    int size = 10; //assumed initial size of the url
    int num_char = 0; //number of current character to track indexing or url

	char *url = malloc(size);
    char domain[100]; //assuming domain name cannot be more that 100 characters

    struct hostent *host_info; // stores pointer to struct returned by gethostbyname()(data of the host)

    struct in_addr **addr_list; // stores pointer of h_addr_list(from gethostbyname)
    //  which points to the list of pointers 
    // pointing to binary IPv4 address;

    int ip_address; // stores binary ipv4 address of the server
    int PORT = 443; // default for HTTP

    int sockfd;
    // struct sockaddr_in server_address;

    //--------------------------------
    //  getting url from the user
    //--------------------------------
	printf("Enter url : ");
	
	while(1){
		char c;
		scanf("%c", &c);
		
		if(c == '\n'){
            if(num_char + 1 < size){
                int size_diff = size - (num_char);
                size = size - size_diff;
                char *new_url = realloc(url, size);

                if(new_url == NULL){
                    printf("Memory allocation failed");
                    exit(1);
                }
                url = new_url;
            }// since we are doubling the size it 
            // is possible that all buffer whole buffer 
            // might not be filled. 
            // So size is shrinked here to save memeory

			break;
		}// break the loop if user presses the enter

        if(num_char >= size){
            size = size * 2;
            char *new_url = realloc(url, size);
            if(new_url == NULL){
                printf("Memory allocation failed");
                exit(1);
            }
            url = new_url;
        }// if nuumber of character + 1(due to 0 based indexing) 
        // is equal or greater than size(means no more characters 
        // can be stored in current memory size) 
        // then double the size of memory
        
        url[num_char] = c;
        num_char++;
	}

    //--------------------------------------
    //  Extracting domain name from url
    //--------------------------------------

    int starting_index = 8; // starting search after https://
    int domain_index = 0;

    for(int i = starting_index; url[i] != '/' && i < size; i++){
        domain[domain_index] = url[i];
        domain_index++;
    }

    domain[domain_index] = '\0';

    //--------------------------------------
    //  Extracting path from url
    //--------------------------------------

    int path_size = size - strlen(domain) - 8;
    char *path = malloc(path_size);
    int path_starting_index = 8 + strlen(domain);
    int path_index = 0;

    for(int i = path_starting_index; i < size; i++){
        path[path_index] = url[i];
        path_index++;
    }

    path[path_index] = '\0';

    //-----------------------------------------
    //  converting domain name to ip address
    //-----------------------------------------

    host_info = gethostbyname(domain); // returns a pointer to the struct of type hostent
    addr_list = (struct in_addr **)host_info->h_addr_list;

    if(host_info == NULL){
        printf("In valid domain name\n");
        exit(1);
    }


    //----------------------------------------
    //  Setting up TCP socket with SSL wrap
    //----------------------------------------

    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;

    send_request(path, domain, path_size, size, NULL, 0, NULL, addr_list, &ctx, &ssl, &sockfd);

    //-------------------------------------------
    //  Receiving requested data
    //-------------------------------------------

    char response[65536]; 
    char *body = NULL;
    char status_code[4];

    get_response(response, sizeof(response), &body, status_code, ssl);
    if(strcmp(status_code, "200") == 0){
        printf("Download complete\n");
    }

    //------------------------------------------------
    //  Checking login status for private files
    //------------------------------------------------

    char session_id[500];
    char *set_cookie_pointer = strstr(response, "Set-Cookie");

    if(set_cookie_pointer != NULL){
        char *session_id_key_pointer = set_cookie_pointer + 12;
        char session_id_key[100]; //assuming key cannot be more than 10 characters long

        int index;
        for(index = 0; *(session_id_key_pointer + index) != '='; index++){
            session_id_key[index] = *(session_id_key_pointer + index);
        }
        session_id_key[index] = '\0';

        printf("\nRequested file is protected...\n");
        printf("Plaease enter session_id : ");
        scanf("%s", session_id);

        send_request(path, domain, path_size, size, session_id, sizeof(session_id), session_id_key, addr_list, &ctx, &ssl, &sockfd); //sending request again with session id
        response[0] = '\0'; //empty buffers
        body = NULL;
        status_code[0] = '\0';
        get_response(response, sizeof(response), &body, status_code, ssl); //reading data again

        if(strcmp(status_code, "200") == 0){
            printf("Download complete\n");
        }else{
            printf("Something went wrong\n");
            exit(1);
        }
    }

    printf("\nHeader:\n%s\n", response);
    printf("\nBody:\n%s\n", body);

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sockfd);
    SSL_CTX_free(ctx);
}