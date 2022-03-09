#include "stdafx.h"

#ifndef Utils_H
#define Utils_H

class Utils
{
public:
        static string convertToHex(unsigned char* arr, int size);
        static unsigned char* convertToBinary(string data); 
        static void fillCharArray(string data, int length, char* arr);
        static long getFileSize(string fileName);
        static string validateSingleFile(string path);
        static bool shredFile(string fileName);
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
        unlink(fileName.c_str());
        return true;
}