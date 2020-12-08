#include <iostream>
#include "ytp.h"
#include "../user.h"
#include <cstring>
using namespace std;

Ytp::Ytp(char *type, char *status, int code, int len)
{
    this->type = new char[100];
    strcpy(this->type, type);
    this->status = new char[100];
    strcpy(this->status, status);
    this->code = code;
    this->len = len;
    this->content = new char[300 + User::name_len];
    int pre_len;
    //cout << "debug:in ytp" << endl;
    pre_len = sprintf(content, "TYPE:%s\r\nSTATUS:%s\r\nCODE:%d\r\nLENGTH:%d\n", type, status, code, len);
}
Ytp::~Ytp()
{
    delete[] type;
    delete status;
    delete[] content;
}
char *Ytp::parser(char *message)
{
    int n;
    n = sscanf(message, "TYPE:%s\nSTATUS:%s\nCODE:%d\nLENGTH:%d\n", type, status, &code, &len);
    int lines = 4;
    char *pos = message;
    for (int i = 0; i < lines;)
    {
        if (*pos == '\n')
        {
            i++;
        }
        pos++;
    }
    return pos;
}
Ytp::Ytp()
{
    this->type = new char[100];
    this->status = new char[100];
    this->content = new char[300 + User::name_len];
}
