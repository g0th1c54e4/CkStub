#include <iostream>
#include <Windows.h>
using namespace std;

int main() {
	CHAR lpFilePath[MAX_PATH] = {0};
	cout << "[*]键入需要加壳的程序路径:";
	cin >> lpFilePath;

	return 0;
}