#include "stdafx.h"

#ifndef Utils_H
#define Utils_H

class Utils
{
public:
        static string convertToHex(char* arr, int size);
        static char* convertToBinary(string data); 
        static void fillCharArray(string data, char* arr);
        static long getFileSize(string fileName);
};

#endif // !Utils_H

string Utils::convertToHex(char* arr, int size)
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
char* Utils::convertToBinary(string data)
{
        int len = data.length();
        char* newArr = new char[data.length() / 2 +1]; // Divided by 2 bc it is hex to bytes.
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

void Utils::fillCharArray(string data, char* arr)
{
        for (int i = 0; i < data.length(); i++) {
                arr[i] = data[i];
        }

        for (int i = data.length(); i < 100; i++) {
                arr[i] = '\x00';
        }
}

long Utils::getFileSize(string fileName) 
{
        struct stat st;
        stat(fileName.c_str(), &st);
        return st.st_size;
}