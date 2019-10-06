// test.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "pch.h"
#include <iostream>
#include <errhandlingapi.h>
#include "ras_assert.h"

class SomeClass {

public:
	void Do() {
		DoImpl();
	}

private:
	void DoImpl() {

		RAS_ASSERT(false || "Check if something wrong happened!");

	}
};


int main()
{
	const DWORD ver[] = { 1,0,0,0 };
	if (InitializeDump(TEXT("c:\\code\\tmp"), TEXT("RAS"), TEXT("test"), ver, -1) == ERROR_SUCCESS) {
		std::cout << "Dump successfuly initialized" << std::endl;

		SomeClass test;
		test.Do();

		std::cout << "Done" << std::endl;
	}

}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
