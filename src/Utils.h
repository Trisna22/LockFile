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
        static long getFileSize(string fileName);
        static string validateSingleFile(string path);
        static bool shredFile(string fileName);
        static char* requirePassword();
        static void printProgressBar(float progress);
        static bool copyFileDataToFilePointer(string fileName, FILE* outputFile);
        static bool copyFileBufferToFilePointer(FILE* inputFile, unsigned long fileSize, FILE* outputFile);
        static void hexdump(void*ptr, int size);
        static string setFolderNaming(string target);
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
        if (path.find("/") != string::npos) {

                return path.substr(path.find_last_of("/")+1);
        }

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

/**
 * Writes the content of the target filename to the given output file pointer.
 * 
 * @param fileName The target file fileName.
 * @param outputFile The pointer to the file descriptor.
 */
bool Utils::copyFileDataToFilePointer(string fileName, FILE* outputFile)
{
        // Open the encrypted file.
        FILE* inputFile = fopen(fileName.c_str(), "rb");
        if (inputFile == NULL) {

                printf("[-] Failed to open the encrypted file %s! Error code: %d\n\n", fileName.c_str(), errno);
                return false;
        }

        /**
         * @brief sendfile() not possible here
         * 
         * The problem with this bit is that we want to copy the
         * file data to a certain offset in the output file. 
         * sendfile() doesn't support that for the offset, so we can't
         * use it for now.
         */

        // // To get the file size.
        // fseek(inputFile, 0, SEEK_END);
        // unsigned long fileSize = ftell(inputFile);
        // rewind(inputFile);

        // if (sendfile64(outputFile->_fileno, inputFile->_fileno, NULL, fileSize) == -1) {

        //         printf("[-] Failed to copy the bytes to output file! Error code: %d\n\n", errno);
        //         return false;  
        // }
        // return true;

        // Read the content of encrypted file and write
        // into the output file.
        char* buffer = (char*)malloc(READ_SIZE);
        int totalBytes = 0;
        for (;;) {

                int readSize = fread(buffer, 1, READ_SIZE, inputFile);
                if (readSize <= 0 && errno != 0) {

                        printf("[-] Failed to read buffer from input file! Error code: %d\n\n", errno);
                        return false;
                }
                else if (readSize <= 0 && errno == 0)
                        break;

                // Write to output file.
                if (fwrite(buffer, 1, readSize, outputFile) <= 0) {
                        printf("[-] Failed to write the file data into the output file! Error code: %d\n\n", errno);
                        return false;
                }
        
                totalBytes += readSize;
        }

        // Delete the encrypted file. 
        fclose(inputFile);
        free(buffer);
        return true;
}

/**
 * Copies the partial content of the input file to the output file.
 * 
 * @param inputFile The input file pointer to read the buffer from.
 * @param fileSize  The size of the buffer to read.
 * @param outputFile The pointer to the output file.
 */
bool Utils::copyFileBufferToFilePointer(FILE* inputFile, unsigned long fileSize, FILE* outputFile)
{
        // Get the offset to keep track on.
        __off64_t currentOffset = ftell(inputFile);

        if (sendfile64(outputFile->_fileno, inputFile->_fileno, &currentOffset,  fileSize) == -1) {
                printf("[-] Failed to copy the bytes from input file! Error code: %d\n\n", errno);
                return false;
        }

        // Adjust the offset again for the input file.
        fseek(inputFile, currentOffset, SEEK_SET);
        fclose(outputFile);

        return true;

        /**
         * @brief 
         * 
         * Dead code, because we have a solution to shorten this with the sendfile() syscall.
         * 
         **/
        // char* buffer = (char*)malloc(READ_SIZE);

        // // When the size of the file is smaller than the read size.
        // if (fileSize < READ_SIZE) {

        //         int readSize = fread(buffer, 1, fileSize, inputFile);
        //         if (readSize <= 0 && errno != 0) {
        //                 printf("[-] Failed to read buffer from input file! Error code: %d\n\n", errno);
        //                 return false;
        //         }

        //         if (fwrite(buffer, 1, readSize, outputFile) <= 0) {

        //                 printf("[-] Failed to write the input data to the output file! Error code: %d\n\n", errno);
        //                 return false;
        //         }   

        //         // Cleanup, WARNING: Do not close the inputFile, we still need it.
        //         free(buffer);
        //         fclose(outputFile);    
        //         return true; 
        // }

        // unsigned long counter = fileSize;
        // while (counter != 0) {

        //         // Write data to output.
        //         int readSize;
        //         if (counter < READ_SIZE) {
        //                 readSize = fread(buffer, 1, counter, inputFile);
        //                 counter -= counter;
        //         }
        //         else {
        //                 readSize = fread(buffer, 1, READ_SIZE, inputFile);
        //                 counter -= READ_SIZE;
        //         }
              
        //         if (readSize <= 0) {

        //                 printf("[-] Failed to read buffer from input file! Error code: %d\n\n", errno);
        //                 return false;
        //         }
              
        //         if (fwrite(buffer, 1, readSize, outputFile) <= 0) {

        //                 printf("[-] Failed to write the input data to the output file! Error code: %d\n\n", errno);
        //                 return false;
        //         }
        // }

        // // Cleanup, WARNING: Do not close the inputFile, we still need it.
        // free(buffer);
        // fclose(outputFile);    
        // return true; 
}


void Utils::hexdump(void *ptr, int buflen) {
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

string Utils::setFolderNaming(string target) {
        
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


