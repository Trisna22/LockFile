#include <iostream>
#include <string.h>
#include <sstream>
#include <iomanip>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <vector>
#include <sys/resource.h>

#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <openssl/rsa.h>
#include <openssl/pem.h>

using namespace std;