#include "IPValidator.h"

#include <iostream>
#include <fstream>
#include <exception>
#include <thread>
#include <chrono>

using namespace std;

void processFile(const std::string& fileName)
{
    if (fileName.empty())
        return;

    try
    {
        ifstream fileStream;
        fileStream.open(fileName, ios::ios_base::in);
        if (fileStream.is_open())
        {
            IPValidator ipValidator;
            for (string line; getline(fileStream, line);)
                ipValidator.pushData(line);

            ipValidator.setReadingDataDone(true);
            fileStream.close();
            while (!ipValidator.isProcessingDone())
            {
                this_thread::sleep_for(chrono::microseconds(1));
                continue;
            }
            cout << "Total IPV4 address count  \t= " << ipValidator.getTotalIPV4AddrCnt() << endl;
            cout << "Total IPV6 address count  \t= " << ipValidator.getTotalIPV6AddrCnt() << endl;
            cout << "Unique IPV4 address count \t= " << ipValidator.getUniqueIPV4AddrCnt() << endl;
            cout << "Unique IPV6 address count \t= " << ipValidator.getUniqueIPV6AddrCnt() << endl;
            cout << "Invalid IP address count  \t= " << ipValidator.getInvalidIPAddrCnt() << endl;
        }
        else
        {
            cerr << "Input file can not be opened. Exiting..." << endl;
        }
    }
    catch (const exception& excp)
    {
        cerr << "Exception caught: " << excp.what() << endl;
    }
}

int main(int argc, char** argv)
{
    cout << endl;
    if (argc < 2)
    {
        cerr << "No file provided to process. Returning...." << endl;
    }
    else if (argc > 3)
    {
        cerr << "Too many parameters. Not processing..." << endl;
    }
    else
    {
        if (argc == 2)
        {
            string fileName(argv[1]);
            processFile(fileName);
        }
        else
        {
            string fileName(argv[1]);
            string filePath;

#if defined(_WIN64) || defined(_WIN32)
            filePath = argv[2];
            if (filePath[filePath.size() - 1] == '\'')
                fileName = filePath + fileName;
            else
                fileName = filePath + "\"" + fileName;
#else
            filePath = argv[2];
            if (filePath[filePath.size() - 1] == '/')
                fileName = filePath + fileName;
            else
                fileName = filePath + "/" + fileName;

#endif // _WIN64 || _WIN32

        }
    }
    return 0;
}
