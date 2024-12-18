#include "Util.hpp"
#include "iomanip"
#include "termios.h"
#include "unistd.h"
#include <iostream>

std::string Util::get_password(const std::string &prompt) {
    std::cout << prompt;
    struct termios oldt, newt;
    char c;
    std::string password;

    // get current terminal attributes
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;

    // disable echo
    newt.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);

    // read password from stdin
    while (std::cin.get(c) && c != '\n')
    {
        password += c;
    }

    // restore terminal settings
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    std::cout << std::endl;

    return password;
}

void Util::to_hex(const unsigned char *const data, size_t size)
{
    for (size_t i = 0; i < size; i++)
    {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(data[i]);
    }
}