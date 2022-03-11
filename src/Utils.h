#include "stdafx.h"

#ifndef Utils_H
#define Utils_H

#define PATH_URANDOM                    "/dev/urandom"
#define MIN_ITERATION                   3        
#define MAX_READWRITE_SIZE              4069

class Utils
{
public:
        static string convertToHex(unsigned char* arr, int size);
        static unsigned char* convertToBinary(string data); 
        static void fillCharArray(string data, int length, char* arr);
        static long getFileSize(string fileName);
        static string validateSingleFile(string path);
        static bool shredFile(string fileName);
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

long Utils::getFileSize(string fileName) 
{
        struct stat st;
        stat(fileName.c_str(), &st);
        return st.st_size;
}

string Utils::validateSingleFile(string path)
{
        // Remove the last slash.
        if (path[path.length()-1] == '/' || path[path.length() -1] == '\\')
                path = path.substr(0, path.length() -1);

        // Get only the filename.
        if (path.find("/") != string::npos)
                return path.substr(path.find_last_of("/")+1);

        return path;
}

bool Utils::shredFile(string fileName)
{
        // TODO use our shredder code from our virus.

        int fdSnitch = open(fileName.c_str(), O_WRONLY | O_NOCTTY);
        if (fdSnitch == -1) {

                printf("[-] Failed to open the snitch file %s! Error code: %d\n\n", fileName.c_str(), errno);
                return false;
        }

        // Randomizing the content of the file.
        if (!shredLoop(fdSnitch)) {

                printf("[-] Failed to shred the snitch file with looping!\n\n");
                return false;
        }

        // Zero out the filename.
        if (!Utils::zeroOutFileName(fileName, fdSnitch)) {
                printf("[-] Failed to zero'ing out the snitch file! Error code: %d\n\n", errno);
                close(fdSnitch);
                return false;
        }

        close(fdSnitch);
        return true;
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