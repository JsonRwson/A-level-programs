#include <iostream>BH
#include <string>
#include <ctime>
#include <vector>
using namespace std;

int main()
{   
    string menuChoice;
    cout << "\n1. Generate Password\n2. Exit Program";
    cin >> menuChoice;
    
    if (menuChoice == "2") {
        exit;
    }
    else if (menuChoice == "1") {

        string characters = "abcdefghijklmnopqrstuvwxyzABCDEFDGHIJKLMNOPQRSTUVWXYZ1234567890";
        string password = "";
        srand(time(NULL));
        int charactersLength = characters.length();

        for (int i = 0; i < 10; i++) {
            char selectedChar = characters[(rand() % charactersLength)];
            password.push_back(selectedChar);
        }

        cout << "\n" << password;
    }
}