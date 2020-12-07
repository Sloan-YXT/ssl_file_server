#include "user.h"
#include <cstring>
#include <limits.h>
#include <unistd.h>
using namespace std;
long User::name_len;
User::User(char *name, char *work_dir)
{
    long len = sysconf(_PC_NAME_MAX);
    //name_len = sysconf(_SC_LOGIN_NAME_MAX);
    name = new char[name_len];
    work_dir = new char[len];
    strcpy(this->name, name);
    strcpy(this->work_dir, work_dir);
}
