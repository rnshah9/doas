#include <stdint.h>
#include <stdio.h>
#include <climits>
#include <pwd.h>

#include <fuzzer/FuzzedDataProvider.h>
extern "C" struct passwd * copyenvpw(struct passwd *my_static);

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);

    char* pw_name = strdup(provider.ConsumeRandomLengthString(100).c_str());
    char* pw_passwd = strdup(provider.ConsumeRandomLengthString(100).c_str());
    char* pw_gecos = strdup(provider.ConsumeRandomLengthString(100).c_str());
    char* pw_dir = strdup(provider.ConsumeRandomLengthString(100).c_str());
    char* pw_shell = strdup(provider.ConsumeRandomLengthString(100).c_str());
    __uid_t pw_uid = provider.ConsumeIntegral<__uid_t>();
    __gid_t pw_gid = provider.ConsumeIntegral<__gid_t>();

    struct passwd p;
    p.pw_name = pw_name;
    p.pw_passwd = pw_passwd;
    p.pw_gecos = pw_gecos;
    p.pw_dir = pw_dir;
    p.pw_shell = pw_shell;
    p.pw_uid = pw_uid;
    p.pw_gid = pw_gid;

    copyenvpw(&p);
    return 0;
}