#include <Windows.h>
#include <iostream>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <string>
#include "interface_h.h"
#include <wscapi.h>
#include <comdef.h>
#include <iwscapi.h>
#pragma comment(lib, "wscapi.lib")
#pragma comment(lib, "rpcrt4.lib")

handle_t hToken = 0;
HRESULT hr;
using namespace std;

void* __RPC_USER midl_user_allocate(size_t size){
	return malloc(size);
}

void __RPC_USER midl_user_free(void* p) {
	free(p); 
}

void HandleError(const string& message) {
	cout << message << endl;
	exit(EXIT_FAILURE); 
}

void Exit(handle_t handle) {
	if (hToken != nullptr) {
		cout << "Client has been disconnected" << endl;
		RevertToSelf();
		CloseHandle(hToken);
		hToken = nullptr;
	}
	else {
		cout << "Client handle is already null" << endl;
	}
}


int Remove(handle_t handle, const unsigned char* path){
	if (ImpersonateLoggedOnUser(hToken)) {
		if (remove((const char*)path) == 0) {
			cout << "Successfully deleted: " << (const char*)path << endl; 
			return 0; 
		} 
		else {
			cout << "Failed to delete file: " << (const char*)path << endl;
			return 1; 
		}
	}
	else {
		cout << "Failed to impersonate user" << endl;
		return 1;
	}
}

int Download(handle_t handle, const unsigned char* src_path, unsigned char* buffer, unsigned int buffer_size) {
	if (ImpersonateLoggedOnUser(hToken)) {
		cout << "Starting download..." << endl;

		FILE* file = NULL;
		fopen_s(&file, (const char*)src_path, "rb");

		if (file) {
			memset(buffer, 0, buffer_size);

			if (fread(buffer, sizeof(char), buffer_size, file) != buffer_size) {
				cout << "Download failed: Error reading file" << endl;
				fclose(file);
				return 1;
			}

			cout << "Download successful" << endl;
			fclose(file);
			return 0;
		}
		else {
			cout << "Download failed" << endl; 
			return 1;
		}
	}
	else { 
		cout << "Failed to impersonate user" << endl;
		return 1; 
	}
}

int Upload(void* handle, const unsigned char* src_path, const unsigned char* buffer, unsigned int buffer_size) {
	if (ImpersonateLoggedOnUser(hToken)) {
		cout << "Starting uploading..." << endl;

		FILE* file = NULL;
		fopen_s(&file, (const char*)src_path, "rb");

		if (file) {
			if (fread(&buffer, sizeof(char), buffer_size, file) != buffer_size) {
				cout << "Upload failed: Error reading file" << endl;
				fclose(file);
				return 1;
			}

			cout << "Upload successful" << endl;
			fclose(file);
			return 0;
		}
		else {
			fopen_s(&file, (const char*)src_path, "wb");
			if (file) {
				if (fwrite(buffer, sizeof(char), buffer_size, file) != buffer_size) {
					cout << "Upload failed: Error writing to file" << endl;
					fclose(file);
					return 1;
				}

				cout << "Upload successful" << endl;
				fclose(file);
				return 0;
			}
			else {
				cout << "Upload failed: Unable to create file" << endl;
				return 1;
			}
		}
	}
	else {
		cout << "Failed to impersonate user" << endl;
		return 1;
	}
}

int Authenticate(handle_t handle, unsigned char* username, unsigned char* password) {
	int impersonation_status = 0;
	impersonation_status = LogonUserA((LPCSTR)username, NULL, (LPCSTR)password, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &hToken) 
		& ImpersonateLoggedOnUser(hToken);

	if (impersonation_status) {
		cout << "Authentication successful. Username: " << username << endl;
		return 0;
	}
	else {
		cout << "Authentication failed. Please check your login credentials." << endl;
		return 1;
	}
}

unsigned int FileSize(handle_t handle, const unsigned char* path) {
	FILE* file = NULL;
	fopen_s(&file, (const char*)path, "rb");

	if (file == NULL) { 
		return 0; 
	}

	fseek(file, 0, SEEK_END);
	int file_size = ftell(file);
	fclose(file);

	return file_size;
}

int CheckHRESULT(HRESULT hr) {
	if (FAILED(hr)) {
		cout << "Error of get security data" << endl;
		return 0;
	}
	return 1;
}

string printStatus(WSC_SECURITY_PROVIDER_HEALTH status)
{
	switch (status)
	{
	case WSC_SECURITY_PROVIDER_HEALTH_GOOD: return "GOOD";
	case WSC_SECURITY_PROVIDER_HEALTH_NOTMONITORED: return "NOTMONITORED";
	case WSC_SECURITY_PROVIDER_HEALTH_POOR: return "POOR";
	case WSC_SECURITY_PROVIDER_HEALTH_SNOOZE: return "SNOOZE";
	default: return "Status Error";
	}
}

int SecurityData(handle_t hBinding, SecurityStatus* status)
{
	RevertToSelf();
	WSC_SECURITY_PROVIDER_HEALTH health;

	if (S_OK == WscGetSecurityProviderHealth(WSC_SECURITY_PROVIDER_FIREWALL, &health)) {
		status->firewall = (health == WSC_SECURITY_PROVIDER_HEALTH_GOOD);
		cout << "Firewall:          " << printStatus(health) << endl;
	}
	if (S_OK == WscGetSecurityProviderHealth(WSC_SECURITY_PROVIDER_ANTIVIRUS, &health)) {
		status->antivirus = (health == WSC_SECURITY_PROVIDER_HEALTH_GOOD);
		cout << "Antivirus:         " << printStatus(health) << endl;
	}
	if (S_OK == WscGetSecurityProviderHealth(WSC_SECURITY_PROVIDER_AUTOUPDATE_SETTINGS, &health)) {
		status->autoupdate = (health == WSC_SECURITY_PROVIDER_HEALTH_GOOD);
		cout << "Autoupdate:        " << printStatus(health) << endl;
	}
	if (S_OK == WscGetSecurityProviderHealth(WSC_SECURITY_PROVIDER_ANTISPYWARE, &health)) {
		status->antispyware = (health == WSC_SECURITY_PROVIDER_HEALTH_GOOD);
		cout << "Antispy:           " << printStatus(health) << endl;
	}
	if (S_OK == WscGetSecurityProviderHealth(WSC_SECURITY_PROVIDER_INTERNET_SETTINGS, &health)) {
		status->internetSettings = (health == WSC_SECURITY_PROVIDER_HEALTH_GOOD);
		cout << "Internet:          " << printStatus(health) << endl;
	}
	if (S_OK == WscGetSecurityProviderHealth(WSC_SECURITY_PROVIDER_USER_ACCOUNT_CONTROL, &health)) {
		status->uac = (health == WSC_SECURITY_PROVIDER_HEALTH_GOOD);
		cout << "UAC:               " << printStatus(health) << endl;
	}
	if (S_OK == WscGetSecurityProviderHealth(WSC_SECURITY_PROVIDER_SERVICE, &health)) {
		status->service = (health == WSC_SECURITY_PROVIDER_HEALTH_GOOD);
		cout << "Service:           " << printStatus(health) << endl;
	}
	if (S_OK == WscGetSecurityProviderHealth(WSC_SECURITY_PROVIDER_ALL, &health)) {
		status->all = (health == WSC_SECURITY_PROVIDER_HEALTH_GOOD);
		cout << "All:               " << printStatus(health) << endl;
	}


	return 0; // Success
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        cout << "Usage: server <port>" << endl;
        return -1;
    }

    char* serverPort = argv[1];
    RPC_STATUS rpcStatus;

    rpcStatus = RpcServerUseProtseqEpA((RPC_CSTR)"ncacn_ip_tcp", RPC_C_PROTSEQ_MAX_REQS_DEFAULT, (RPC_CSTR)(serverPort), NULL);
    if (rpcStatus != RPC_S_OK) {
        cout << "Failed to use protocol sequence." << endl;
        return -1;
    }

    rpcStatus = RpcServerRegisterIf2(Interface_v1_0_s_ifspec, NULL, NULL, RPC_IF_ALLOW_CALLBACKS_WITH_NO_AUTH, RPC_C_LISTEN_MAX_CALLS_DEFAULT, -1, NULL);
    if (rpcStatus != RPC_S_OK) {
        cout << "Failed to register interface." << endl;
        return -1;
    }

    RPC_BINDING_VECTOR* bindingVector;
    rpcStatus = RpcServerInqBindings(&bindingVector);
    if (rpcStatus != RPC_S_OK) {
        cout << "Failed to inquire bindings." << endl;
        return -1;
    }

    rpcStatus = RpcEpRegister(Interface_v1_0_s_ifspec, bindingVector, NULL, NULL);
    if (rpcStatus != RPC_S_OK) {
        cout << "Failed to register endpoint." << endl;
        return -1;
    }

    hr = CoInitialize(NULL);
    if (FAILED(hr)) {
        cout << "Failed to initialize COM." << endl;
        return -1;
    }

    cout << "Server is starting to listen..." << endl;
    rpcStatus = RpcServerListen(1, RPC_C_LISTEN_MAX_CALLS_DEFAULT, 0);
    if (rpcStatus != RPC_S_OK) {
        cout << "Failed to start listening." << endl;
        CoUninitialize();
        return -1;
    }

    CoUninitialize();
    return 0;
}