#include "PamClass.h"
#include "../ssl_util/ssl_util.h"
#include <unistd.h>
#include <cstring>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/socket.h>
#include <netinet/in.h>
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
    char *p = new char[MAX_PAM_MSG_LEN];
    //read(fd, p, MAX_PAM_MSG_LEN);
    int len;
    int n = recv(fd, &len, sizeof(len), MSG_WAITALL);
    len = ntohl(len);
    printf("len:%d\n", len);
    n = SSL_recv(ssl, p, len);
    if (n <= 0)
    {
        exit(1);
    }
    len = strlen(p);
    if (p[len - 1] == '\n')
    {
        p[len - 1] = 0;
    }
    puts(p);
    printf("leaving getinput!\n");
    return p;
}
void dooutput(PamAct &pam_act, int fd, SSL *ssl)
{
    //write(fd, pam_act.news, strlen(pam_act.news));
    char buffer[1000];
    strcpy(buffer, "TYPE:LOGIN\n");
    sprintf(buffer, "TYPE:LOGIN\nCODE:%d\nSTATUS:SUCCESS\n", pam_act.type);
    strcpy(buffer, pam_act.news);
    int n = SSL_write(ssl, buffer, strlen(buffer) + 1);
    if (n <= 0)
    {
        exit(1);
    }
    //write(fd, "\n", 1);
}