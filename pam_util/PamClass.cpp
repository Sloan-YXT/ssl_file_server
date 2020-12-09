#include "PamClass.h"
#include "../ssl_util/ssl_util.h"
#include <unistd.h>
#include <cstring>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "../ytp_util/ytp.h"
extern int connfd;
PamAct::PamAct()
{
    news = new char[MAX_PAM_MSG_LEN];
}
PamAct::~PamAct()
{
    delete[] news;
}
char *getinput(int echoff, int fd, SSL *ssl)
{
    printf("in getinput!\n");
    char tmp[4096 + 1];
    char *p = new char[MAX_PAM_MSG_LEN];
    //every message in ytp format
    //read(fd, p, MAX_PAM_MSG_LEN);
    int len;
    //int n = recv(fd, &len, sizeof(len), MSG_WAITALL);
    //len = ntohl(len);
    //printf("len:%d\n", len);
    int n = SSL_read(ssl, tmp, 4096 + 1);
    printf("debug in getinput");
    puts(tmp);
    Ytp ytp_login_tmp;
    strcpy(p, ytp_login_tmp.parser(tmp));
    if (n <= 0)
    {
        exit(1);
    }
    // len = strlen(p);
    // if (p[len - 1] == '\n')
    // {
    //     p[len - 1] = 0;
    // }
    puts(p);
    printf("leaving getinput!\n");
    return p;
}
void dooutput(PamAct &pam_act, int fd, SSL *ssl)
{
    char buffer[1000];
    Ytp login_ytp("LOGIN", "SUCCESS", LOGIN_SUCCESS, strlen(pam_act.news) + 1);
    strcpy(buffer, login_ytp.content);
    strcat(buffer, pam_act.news);
    //puts(buffer);
    int n = SSL_write(ssl, buffer, strlen(buffer) + 1);
    if (n <= 0)
    {
        exit(1);
    }
    //write(fd, "\n", 1);
}