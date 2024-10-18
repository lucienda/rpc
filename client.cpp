#include <Windows.h>
#include <iostream>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include "interface_h.h"
#pragma comment(lib, "rpcrt4.lib")

handle_t handle = 0;

using namespace std;

void __RPC_FAR* __RPC_USER midl_user_allocate(size_t size) {
	return (malloc(size));
}

void __RPC_USER midl_user_free(void __RPC_FAR* ptr) {
	free(ptr);
}

string ip;
string port;

void HandleError(const string& message) {
	cout << message << endl;
	exit(EXIT_FAILURE);
}

int Login(char* username, char* password) {
	cout << "Enter username: ";
	cin >> username;

	cout << "Enter password: ";
	cin >> password;

	if (!Authenticate(handle, (unsigned char*)username, (unsigned char*)password)) {
		cout << "Authenticate success" << endl;
		cout << "HandleA: " << handle << endl;
		return 0;
	}
	else {
		cout << "Authentication failed. Try again." << endl;
		return 1;
	}
}

void Download_(void) {
	string src_path;
	string dest_path;
	cout << "The source path to the file on server: ";
	cin >> src_path;

	unsigned int size = FileSize(handle, (unsigned char*)src_path.c_str());

	if (!size) {
		cout << "Access denied" << endl;
		return;
	}

	char* data = new (nothrow) char[size];
	if (!data) {
		cout << "Memory allocation failed" << endl;
		return;
	}

	if (Download(handle, (unsigned char*)src_path.c_str(), (unsigned char*)data, size)) {
		cout << "Access denied" << endl;
		delete[] data;
		return;
	}

	cout << "The destination path: ";
	cin >> dest_path;

	ofstream file(dest_path, ios::binary);
	if (!file) {
		cout << "Failed to open file for writing" << endl;
		delete[] data;
		return;
	}

	file.write(data, size);
	file.close();
	delete[] data;

	cout << "File downloaded successfully" << endl;
}

void Upload_(void) {
	string dest_path;
	string src_path;
	cout << "The source path to the file: "; 
	cin >> src_path;

	ifstream file(src_path, ios::binary);

	if (!file.is_open()) {
		cout << "Error: can't open the file" << endl;
		return;
	}

	file.seekg(0, file.end);
	unsigned int size = file.tellg();
	file.seekg(0, file.beg);

	char* data = new (nothrow) char[size];
	if (!data) {
		cout << "Memory allocation failed" << endl;
		file.close();
		return;
	}

	file.read(data, size);
	file.close();

	cout << "The destination path on server: "; 
	cin >> dest_path;

	if (Upload(handle, (const unsigned char*)dest_path.c_str(), (const unsigned char*)data, size)) {
		cout << "Access denied" << endl;
		delete[] data;
		return;
	}

	delete[] data;
	cout << "File uploaded successfully" << endl;
}

void Remove_(void) {
	string path;
	cout << "The path to file: ";
	cin >> path;

	if (Remove(handle, (const unsigned char*)path.c_str())) {
		cout << "Error: can't delete the file" << endl;
	}
	else {
		cout << "File deleted successfully" << endl;
	}
}

void SecurityData_(void) {
	SecurityStatus securityStatus = { 0 };
	// Печать результатов
	SecurityData(handle, &securityStatus);
	printf("Antivirus: %s\n", securityStatus.antivirus ? "ON" : "OFF");
	printf("Firewall: %s\n", securityStatus.firewall ? "ON" : "OFF");
	printf("AutoUpdate: %s\n", securityStatus.autoupdate ? "ON" : "OFF");
	printf("Antispyware: %s\n", securityStatus.antispyware ? "ON" : "OFF");
	printf("Internet Settings: %s\n", securityStatus.internetSettings ? "ON" : "OFF");
	printf("UAC: %s\n", securityStatus.uac ? "ON" : "OFF");
	printf("Service: %s\n", securityStatus.service ? "ON" : "OFF");
	printf("All: %s\n", securityStatus.all ? "ON" : "OFF");
}

int Menu(void) {
	char username[256];
	char password[256];

	while (Login(username, password));
		
	//system("cls");

	int action = 1;
	while (1) {
		cout << "Client actions:" << endl;
		cout << "1 - Change user" << endl;
		cout << "2 - Download file from server" << endl;
		cout << "3 - Upload file to server" << endl;
		cout << "4 - Remove file from server" << endl;
		cout << "5 - Get Security info from server" << endl;
		cout << "6 - Finish" << endl;

		cin >> action;

		switch (action) {
		case 1: {
			Exit(handle);
			RpcBindingFree(&handle);

			RPC_STATUS rpcStatus;

			unsigned char* bind = NULL;

			rpcStatus = RpcStringBindingComposeA(NULL, (RPC_CSTR)("ncacn_ip_tcp"), (RPC_CSTR)(ip.c_str()), (RPC_CSTR)(port.c_str()), NULL, &bind);
			if (rpcStatus) {
				HandleError("Error: failed to create a string binding descriptor");
			}

			rpcStatus = RpcBindingFromStringBindingA(bind, &handle);
			if (rpcStatus) {
				HandleError("Error: failed to create binding from string descriptor");
			}

			while (Login(username, password));

			break;
		}
		case 2:
			Download_();
			break;
		case 3:
			Upload_();
			break;
		case 4:
			Remove_();
			break;
		case 5:
			SecurityData_();
			break;
		case 6:
			Exit(handle);
			RpcBindingFree(&handle);
			exit(1);
		default:
			cout << "Wrong action, try again" << endl;
		}
	}
}

int main(int argc, char* argv[]) {

	if (argc != 2) {
		HandleError("Usage: client <ip:port>");
	}

	string server_address = argv[1];

	ip = server_address.substr(0, server_address.find(':'));
	port = server_address.substr(server_address.find(':') + 1);

	RPC_STATUS rpcStatus;

	unsigned char* bind = NULL;

	rpcStatus = RpcStringBindingComposeA(NULL, (RPC_CSTR)("ncacn_ip_tcp"), (RPC_CSTR)(ip.c_str()), (RPC_CSTR)(port.c_str()), NULL, &bind);
	if (rpcStatus) {
		HandleError("Error: failed to create a string binding descriptor");
	}

	rpcStatus = RpcBindingFromStringBindingA(bind, &handle);
	if (rpcStatus) {
		HandleError("Error: failed to create binding from string descriptor");
	}

	return Menu();
}