#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include <wininet.h>  
#include "beacon.h"

DECLSPEC_IMPORT HINTERNET WINAPI WININET$InternetOpenA(LPCSTR,DWORD,LPCSTR,LPCSTR,DWORD);
DECLSPEC_IMPORT HINTERNET WINAPI WININET$InternetConnectA(HINTERNET,LPCSTR,INTERNET_PORT,LPCSTR,LPCSTR,DWORD,DWORD,DWORD);
DECLSPEC_IMPORT HINTERNET WINAPI WININET$HttpOpenRequestA(HINTERNET,LPCSTR,LPCSTR,LPCSTR,LPCSTR,LPCSTR *,DWORD,DWORD);
DECLSPEC_IMPORT BOOL WINAPI WININET$HttpSendRequestA(HINTERNET,LPCSTR,DWORD,PVOID,DWORD);
DECLSPEC_IMPORT BOOL WINAPI WININET$InternetReadFile(HINTERNET,PVOID,DWORD,PDWORD);
DECLSPEC_IMPORT BOOL WINAPI WININET$HttpQueryInfoA(HINTERNET,DWORD,PVOID,PDWORD,PDWORD);
DECLSPEC_IMPORT BOOL WINAPI WININET$InternetCloseHandle(HINTERNET);

DECLSPEC_IMPORT WINBASEAPI void WINAPI KERNEL32$OutputDebugStringA (LPCSTR);
DECLSPEC_IMPORT WINBASEAPI int WINAPI KERNEL32$lstrlenA(LPCSTR);
DECLSPEC_IMPORT char *__cdecl MSVCRT$strtok(char * __restrict__ _Str,const char * __restrict__ _Delim);
WINBASEAPI char WINAPI MSVCRT$strcat(char *destination, const char *source);
DECLSPEC_IMPORT int __cdecl MSVCRT$strcmp(const char *_Str1,const char *_Str2);

void sendHttpRequest(char * method, char *host, char *uri, int port, char * useragent, char * headers, char * body, int tls, int printoutput){

	HINTERNET hIntSession = WININET$InternetOpenA(useragent, INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    HINTERNET hHttpSession = WININET$InternetConnectA(hIntSession, host, port, 0, 0, INTERNET_SERVICE_HTTP, 0, 0);

    DWORD internetFlags;
    if (tls == 1){
	    internetFlags = INTERNET_FLAG_RELOAD |INTERNET_FLAG_SECURE;
	} else {
		internetFlags = INTERNET_FLAG_RELOAD;
	}

	HINTERNET hHttpRequest = WININET$HttpOpenRequestA(
      hHttpSession, 
      method, 
      uri,
      0, 0, 0, internetFlags, 0);

    if( !WININET$HttpSendRequestA(hHttpRequest, headers, KERNEL32$lstrlenA(headers), body, KERNEL32$lstrlenA(body))) {
      BeaconPrintf(CALLBACK_ERROR, "No response.");
    }
    else {
	    int statusCode;
		char responseText[256];
		DWORD responseTextSize = sizeof(responseText);

		//Check existance of page (for 404 error)
		if(!WININET$HttpQueryInfoA(hHttpRequest, HTTP_QUERY_STATUS_CODE, &responseText, &responseTextSize, NULL)){
			BeaconPrintf(CALLBACK_ERROR, "Retrieving HTTP Request info failed");
		}
		BeaconPrintf(CALLBACK_OUTPUT, "Response Code: %s\n", responseText);


		if(printoutput == 1){
			CHAR szBuffer[1025];
	    	DWORD dwRead=0;

		    while(WININET$InternetReadFile(hHttpRequest, szBuffer, sizeof(szBuffer)-1, &dwRead) && dwRead) {
				szBuffer[dwRead] = 0;
				BeaconPrintf(CALLBACK_OUTPUT, "%s", szBuffer);
			    dwRead=0;
		    }

		}
    } 
    WININET$InternetCloseHandle(hHttpRequest);
    WININET$InternetCloseHandle(hHttpSession);
    WININET$InternetCloseHandle(hIntSession);
}


void go(char *args, int len) {
	datap parser;	
	BeaconDataParse(&parser, args, len);
		
	CHAR * host;
	CHAR * trimmed_host;
	int port = 0;
	int tls = 0;
	CHAR * method; 
	int printoutput;
	CHAR * useragent;
	char * headers;
	CHAR * body;

	host = trimmed_host = BeaconDataExtract(&parser, NULL);
	port = BeaconDataInt(&parser);
	method = BeaconDataExtract(&parser, NULL);
	printoutput = BeaconDataInt(&parser);
	useragent = BeaconDataExtract(&parser, NULL);
	headers = BeaconDataExtract(&parser, NULL);
	body = BeaconDataExtract(&parser, NULL);
	
	int uri_element = 0;
    char * token = NULL;
    char * chunk;
    char uri[1000] = "";
    const char s[2] = "/"; //delimiter

    token = MSVCRT$strtok(host, s);

    while( token != NULL ) {
    	if(MSVCRT$strcmp(token, "http:") == 0){
    		if (port == 0) { port = 80; }
    		tls = 0;
    		uri_element++;
    	} else if(MSVCRT$strcmp(token, "https:") == 0){
    		if (port == 0) { port = 443; }
    		tls = 1;
    		uri_element++;
    	} else if(uri_element == 2){
    		trimmed_host = token;
	    } else if (uri_element > 2) {
	    	MSVCRT$strcat(uri, s);
	    	MSVCRT$strcat(uri, token);
	    }
        token = MSVCRT$strtok(NULL, s);
	    uri_element++;
    }

    if (port == 0) { port = 80; }
 
    BeaconPrintf(CALLBACK_OUTPUT, "%s %s:%i %s\nUser Agent: %s\n%s\n", method, trimmed_host, port, uri, useragent, headers);
   	
	sendHttpRequest(method, trimmed_host, uri, port, useragent, headers, body, tls, printoutput);
}