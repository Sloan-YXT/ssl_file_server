#include <regex>
#include <security/pam_appl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <iostream>
#include <cstring>
#include <cstdlib>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "user.h"
#include "ssl_util/ssl_util.h"
#include "pam_util/PamClass.h"
#include "pam_util/login.h"
#include "ytp_util/ytp.h"
using namespace std;
int sockfd, connfd;
#define PORT 9090
extern PamStatus err_mark;
#define ERR_ACTION(f, a) \
    do                   \
    {                    \
        if (f < 0)       \
        {                \
            perror(a);   \
            exit(1);     \
        }                \
    } while (0);
#define SSL_ERR_ACTION(f, a)             \
    do                                   \
    {                                    \
        if (f <= 0)                      \
        {                                \
            perror(a);                   \
            ERR_print_errors_fp(stdout); \
            exit(1);                     \
        }                                \
    } while (0);
SSL_CTX *ctx;
SSL *ssl;
void client_clean_up(void)
{
    perror("");
    ERR_print_errors_fp(stdout);
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(connfd);
}
int main(void)
{
    User::len = sysconf(_PC_NAME_MAX);
    User::name_len = sysconf(_SC_LOGIN_NAME_MAX);
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    ctx = SSL_CTX_new(SSLv23_server_method());
    if (SSL_CTX_use_certificate_file(ctx, "/home/yaoxuetao/桌面/语言项目实践/keys/cacert.pem", SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stdout);
        exit(1);
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, "/home/yaoxuetao/桌面/语言项目实践/keys/privkey.pem", SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stdout);
        exit(1);
    }
    if (!SSL_CTX_check_private_key(ctx))
    {

        ERR_print_errors_fp(stdout);

        exit(1);
    }
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in server, client;
    socklen_t server_len = sizeof(server), client_len = sizeof(client);
    memset(&server, server_len, 0);
    memset(&client, client_len, 0);
    int res;
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = 0;
    //server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons(PORT);
    ERR_ACTION(res = ::bind(sockfd, (sockaddr *)&server, server_len), "bind error");
    ERR_ACTION(listen(sockfd, 1024), "listen failed");
    int pid;
    while (1)
    {
        connfd = accept(sockfd, (sockaddr *)&client, &client_len);
        ERR_ACTION(connfd, "accept failed");
        pid = fork();
        switch (pid)
        {
        case 0:
        {
            atexit(client_clean_up);
            close(sockfd);
            ssl = SSL_new(ctx);
            SSL_set_fd(ssl, connfd);
            if (SSL_accept(ssl) == -1)
            {

                perror("accept");

                close(connfd);

                exit(1);
            }
            err_mark.ssl = ssl;
            err_mark.fd_err = connfd;
            err_mark.fd_in = connfd;
            err_mark.fd_out = connfd;
            char login_buffer[1024];
            const char *login_tips1 = "your username:";
            const char *login_tips2 = "login success,congratulations!";
        restart:
            Ytp login_ytp_pre("LOGIN", "SETUP", LOGIN_PROC, strlen(login_tips1) + 1);
            strcpy(login_buffer, login_ytp_pre.content);
            strcat(login_buffer, login_tips1);
            int n = SSL_write(ssl, login_buffer, strlen(login_buffer) + 1);
            SSL_ERR_ACTION(n, "ssl write failed in 81");
            char name_buf[4096 + 1];
            int len;
            printf("debug:%d\n", __LINE__);
            // n = recv(connfd, &len, sizeof(len), MSG_WAITALL);
            // ERR_ACTION(n, "recv failed in 115");
            // len = ntohl(len);
            n = SSL_read(ssl, name_buf, 4096 + 1);
            char *name = login_ytp_pre.parser(name_buf);
            //printf("%d", SSL_get_error(ssl, n));
            SSL_ERR_ACTION(n, "ssl read failed in 113");
            int res;
            do
            {
                res = pam_login(name);
                char buffer[4096];
                if (res < 0)
                {
                    //puts(name);
                    Ytp login_ytp_res("LOGIN", "FIALURE", LOGIN_FAILURE, strlen(err_mark.tips) + 1);
                    strcpy(buffer, login_ytp_res.content);
                    strcat(buffer, err_mark.tips);
                    n = SSL_write(ssl, buffer, strlen(buffer) + 1);
                    SSL_ERR_ACTION(n, "ssl write failed in 121");
                    if (err_mark.suberr == BEFOREAUTH)
                        goto restart;
                }
                else
                {
                    Ytp login_ytp_res("LOGIN", "SUCCESS", LOGIN_SUCCESS, strlen(login_tips2) + 1);
                    //puts(login_ytp.content);
                    strcpy(buffer, login_ytp_res.content);
                    strcat(buffer, login_tips2);
                    n = SSL_write(ssl, buffer, strlen(buffer) + 1);
                    SSL_ERR_ACTION(n, "ssl write failed in 126");
                }
            } while (res < 0);
            while (1)
            {
            }
            break;
        }
        default:
            close(connfd);
            break;
        }
    }
}