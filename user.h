class User
{
public:
    static long name_len;
    char *work_dir;
    char *name;
    User();
    User(char *name, char *work_dir);
    ~User();
};