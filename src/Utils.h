#include "stdafx.h"

#ifndef Utils_H
#define Utils_H

#define PATH_URANDOM                    "/dev/urandom"
#define MIN_ITERATION                   3        
#define MAX_READWRITE_SIZE              4069
#define BAR_WIDTH                       70
#define READ_SIZE                       4096

class Utils
{
public:
        static string convertToHex(unsigned char* arr, int size);
        static unsigned char* convertToBinary(string data); 
        static void fillCharArray(string data, int length, char* arr);
        static off64_t getFileSize(string fileName);
        static string validateSingleFile(string path);
        static bool shredFile(string fileName);
        static char* requirePassword();
        static void printProgressBar(float progress);
        static bool copyFileDataToFilePointer(string fileName, FILE* outputFile);
        static bool copyFileBufferToFilePointer(FILE* inputFile, unsigned long fileSize, FILE* outputFile);
        static void hexdump(void*ptr, int size);
        static string setFolderNaming(string target);
        static bool cleanupLooseEnds(string target, bool isFolder);
        static bool md5SumFile(string fileName, unsigned char* fileHash);
        static ushort getPermissions(string path);
        static bool setPermissions(string path, ushort perm);
        static char* displayPermissions(ushort perm);
private:
        static bool shredLoop(int fdSnitch);
        static string getAbsolutePath(string fileName);
        static bool zeroOutFileName(string fileName, int fdSnitch);
};

#endif // !Utils_H

string Utils::convertToHex(unsigned char* arr, int size)
{
        stringstream ss;
        ss << hex << std::setfill('0');
        for (size_t i = 0; size > i; ++i)
        {
                ss << setw(2) << static_cast<unsigned int>(
                        static_cast<unsigned char>(arr[i]));
        }
        string result = ss.str();
        ss.clear();
        return result;
}
unsigned char* Utils::convertToBinary(string data)
{
        int len = data.length();
        unsigned char* newArr = new unsigned char[data.length() / 2 +1]; // Divided by 2 bc it is hex to bytes.
        int counter = 0;
        for (int i = 0; i < len; i += 2)
        {
                string byte = data.substr(i, 2); 
                char chr = (char) (int) strtol(byte.c_str(), 0, +16);
                newArr[counter++] = chr;
        }
        newArr[counter] = '\0'; // To put the string termination at the end.
        return newArr;
}

void Utils::fillCharArray(string data, int length, char* arr)
{
        memcpy(arr, data.c_str(), length);
        arr[length] = '\0';
}

off64_t Utils::getFileSize(string fileName) 
{
        struct stat64 st;
        stat64(fileName.c_str(), &st);
        return st.st_size;
}

string Utils::validateSingleFile(string path)
{
        // Remove the last slash.
        if (path[path.length()-1] == '/' || path[path.length() -1] == '\\')
                path = path.substr(0, path.length() -1);

        // Get only the filename.
        if (path.find("/") != string::npos) {

                return path.substr(path.find_last_of("/")+1);
        }

        return path;
}

bool Utils::shredFile(string fileName)
{
        int fdSnitch = open(fileName.c_str(), O_WRONLY | O_NOCTTY);
        if (fdSnitch == -1) {

                printf("-> Failed to open the snitch file %s! Error code: %d\n\n", fileName.c_str(), errno);
                return false;
        }

        // Randomizing the content of the file.
        if (!shredLoop(fdSnitch)) {

                printf("-> Failed to shred the snitch file with looping!\n\n");
                return false;
        }

        close(fdSnitch);

        // Zero out the filename.
        if (!Utils::zeroOutFileName(fileName, fdSnitch)) {
                printf("-> Failed to zero'ing out the snitch file! Error code: %d\n\n", errno);
                close(fdSnitch);
                return false;
        }

        return true;
}

char* Utils::requirePassword() 
{
        char* password = getpass("Password to use: ");
        return password;
}

void Utils::printProgressBar(float progress)
{
        printf(" [");
        int pos = BAR_WIDTH * progress;
        for (int j = 0; j < BAR_WIDTH; j++) {
                if (j < pos) printf("=");
                else if (j == pos) printf(">");
                else printf(" ");
        }
        printf("] %f %\r", progress *100.0);
        if (progress == 1.0)
                printf("\n");
}

void Utils::hexdump(void *ptr, int buflen)
{
        unsigned char *buf = (unsigned char*)ptr;
        int i, j;
        for (i=0; i<buflen; i+=16) {

                printf("%06x: ", i);
                for (j=0; j<16; j++) 
                        if (i+j < buflen)
                                printf("%02x ", buf[i+j]);
                        else
                                printf("   ");
                printf(" ");
                for (j=0; j<16; j++) 
                        if (i+j < buflen)
                                printf("%c", isprint(buf[i+j]) ? buf[i+j] : '.');
                printf("\n");
        }
}

string Utils::setFolderNaming(string target) 
{
        
        struct stat fstat;
        stat(target.c_str(), &fstat);

        // If it is a folder.
        if (S_ISDIR(fstat.st_mode)) {

                // Check if it has a trailing end-slash.
                if (target[target.length() -1] == '/') {
                        target = target.substr(0, target.length() -1);
                }
        }

        return target;
}

bool Utils::cleanupLooseEnds(string target, bool isFolder) 
{
        if (!isFolder) {
                return Utils::shredFile(target);
        }

        DIR* dirHandler = opendir(target.c_str());
        if (dirHandler == 0) {
                printf("-> Failed to open the directory for deleting %s!\n\n Error code: %d\n", target.c_str(), errno);
                return false;
        }

        struct dirent* fileHandler;
        while (fileHandler = readdir(dirHandler)) {

                if ((string)fileHandler->d_name == "." || (string)fileHandler->d_name == "..")
                        continue;

                if (fileHandler->d_type == DT_DIR) {

                        if (!Utils::cleanupLooseEnds(target + "/" + fileHandler->d_name, true)) {
                                return false;
                        }
                }
                else {
                        if (!Utils::shredFile(target + "/" + fileHandler->d_name)) {
                                return false;
                        }
                }
        }

        closedir(dirHandler);

        // Delete this folder.
        if (rmdir(target.c_str()) == -1) {

                printf("-> Failed to remove folder %s! Error code: %d\n\n", target.c_str(), errno);
                return false;
        }
        
        return true;
}

/**
 * Generates the MD5 hash of the content of the given file.
 * 
 * @param fileName The file to get the hash from.
 * @param fileHash The pointer to store the hash in.
 */
bool Utils::md5SumFile(string fileName, unsigned char* fileHash)
{
        EVP_MD_CTX *hashContext = EVP_MD_CTX_create();
	EVP_MD_CTX_init(hashContext);
	if (EVP_DigestInit_ex(hashContext, EVP_md5(), NULL) == 0) {
                printf("-> Failed to init a digest object! Error code: %d\n\n", errno);
                return false;
        }

	int hashLen = EVP_MD_size(EVP_md5());
        unsigned char* buffer = (unsigned char*)malloc(READ_SIZE);

        FILE* inputFile = fopen(fileName.c_str(), "rb");
        if (inputFile == NULL) {

                printf("-> Failed to open the file %s for hashing! Error code: %d\n\n", fileName.c_str(), errno);
                return false;
        }
        
        for (;;) {
                int readSize = fread(buffer, sizeof(unsigned char), READ_SIZE, inputFile);
                if (readSize <= 0 && errno != 0) {

                        printf("-> Failed to read the file %s for hashing! Error code: %d\n\n", fileName.c_str(), errno);
                        return false;
                }
                else if (readSize <= 0 && errno == 0)
                        break;
                else if (readSize == 0) {

                        printf("-> Failed to create a hash for the file %s! File is empty!\n\n", fileName.c_str());
                        return false;
                }

	        EVP_DigestUpdate(hashContext, buffer, readSize);
        }

	EVP_DigestFinal_ex(hashContext, fileHash, NULL);

        // Cleanup.
        free(buffer);
        fclose(inputFile);
        return true;
}

ushort Utils::getPermissions(string path)
{
        struct stat st;
        stat(path.c_str(), &st);
        return st.st_mode;
}

bool Utils::setPermissions(string path, ushort perm)
{
        if (chmod(path.c_str(), perm) == -1) {

                printf("-> Failed to set permissions for %s to %u! Error code: %d\n\n", path.c_str(), perm, errno);
                return false;
        }

        return true;
}

char* Utils::displayPermissions(ushort perm) {

        char* modeval = new char [sizeof(char) * 9 + 1];
        modeval[0] = (perm & S_IRUSR) ? 'r' : '-';
        modeval[1] = (perm & S_IWUSR) ? 'w' : '-';
        modeval[2] = (perm & S_IXUSR) ? 'x' : '-';
        modeval[3] = (perm & S_IRGRP) ? 'r' : '-';
        modeval[4] = (perm & S_IWGRP) ? 'w' : '-';
        modeval[5] = (perm & S_IXGRP) ? 'x' : '-';
        modeval[6] = (perm & S_IROTH) ? 'r' : '-';
        modeval[7] = (perm & S_IWOTH) ? 'w' : '-';
        modeval[8] = (perm & S_IXOTH) ? 'x' : '-';
        modeval[9] = '\0';
        return modeval;     
}

/**
 *      Private member functions.
 */

/**
 * @brief 
 * 
 * @param fdSnitch 
 * @param fileSize 
 * @return true 
 * @return false 
 */
bool Utils::shredLoop(int fdSnitch)
{
        // Get file size using fstat.
        struct stat st;
        fstat(fdSnitch, &st);
        size_t fileSize = st.st_size;

        int fdRandom = openat(AT_FDCWD, PATH_URANDOM, O_RDONLY);

        char *randomBuffer = (char*)malloc(MAX_READWRITE_SIZE);

        for (int i = 0; i < MIN_ITERATION; i++) {
                
                lseek(fdSnitch, 0, SEEK_SET);

                // Fill our snitch with nonsens.
                unsigned long filePointer = 0;
                while (filePointer <= fileSize) {

                        read(fdRandom, randomBuffer, MAX_READWRITE_SIZE); // Get the urandom buffer.
                        write(fdSnitch, randomBuffer, MAX_READWRITE_SIZE); // Write the urandom buffer.
                        filePointer += MAX_READWRITE_SIZE;
                        
                        // Generate zero buffer.
                        // char* zeroBuffer = new char[65535];
                        // memset(zeroBuffer, 0, 65535);
                        // write(fdSnitch, zeroBuffer, 65535);
                }

                fdatasync(fdSnitch);
        }

        close(fdRandom);
        free(randomBuffer);
        return true;
}

string Utils::getAbsolutePath(string path)
{
        if (path.find("/") == -1)
                return path;
        
        if (path[path.length() -1] == '/') {

                string a = path.substr(0, path.length() -1);
                return a.substr(a.find_last_of("/") +1);
        }

        return path.substr(path.find_last_of("/") +1);
}

bool Utils::zeroOutFileName(string path, int fdSnitch)
{
        // Zero out the filename.
        string fileName = Utils::getAbsolutePath(path);
        string targetFile = path;
        for (int i = 0; i < fileName.length(); i++) {

                // Create zero buffer.
                string newName;
                for (int j = 0; j < fileName.length() - i; j++) {
                        newName.append("0");
                }

                // Rename previous filename to zero buffer.
                rename(targetFile.c_str(), newName.c_str());
                fdatasync(fdSnitch);
                targetFile = newName;
        }       

        // Delete the zero'ed out filename.
        if (unlink(targetFile.c_str()) == -1) {
                return false;
        }

        /**
         * @brief Example zero'ing out the filename.
         * 
         * test.txt -> 00000000
         * 00000000 -> 0000000
         * 0000000 -> 000000
         * 000000 -> 00000
         * 00000 -> 0000
         * 0000 -> 000
         * 000 -> 00
         * 00 -> 0
         * 
         * unlink("0");
         */

        return true;
}


