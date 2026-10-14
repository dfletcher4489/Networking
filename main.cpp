
#include <winsock2.h>
#include <ws2tcpip.h>
#include <processthreadsapi.h>
#include "iphlpapi.h"
#include <stdio.h>
#include "DNS.h"
#include "DNSRoots.h"

#define MB 1024 * 1024

SOCKET Clients[10];
HANDLE ReceptionHandle[10];
char ReceptionArea[5 * MB];

DWORD FuncForThread(void *params)
{
#define DEFAULT_BUFLEN 512

	char recvbuf[DEFAULT_BUFLEN];

	SOCKET clientSocket = *((SOCKET*)params);

	int iResult;

	do {

		iResult = recv(clientSocket, recvbuf, DEFAULT_BUFLEN, 0);
		if (iResult > 0) {
			printf("Bytes received: %d %d\n", iResult, GetCurrentThreadId());
			for (int i = 0; i < iResult; i++)
			{
				printf("%c ", recvbuf[i]);
			}
			printf("\n");
		}
		else if (iResult == 0) {
			printf("Connection closing...\n");
			closesocket(clientSocket);
		}
		else {
			printf("recv failed: %d\n", WSAGetLastError());
			closesocket(clientSocket);
			WSACleanup();
			return 1;
		}
	} while (iResult > 0);

	return 0;
}

HANDLE CreateThreadOfFuncForThread(int address)
{



	DWORD threadID;
	DWORD creationFlags = 0;
	SIZE_T stackSize = 0xffff;
	HANDLE ret;

	ret = CreateThread(
		NULL,
		stackSize,
		FuncForThread,
		&Clients[address],
		creationFlags,
		&threadID
	);

	return ret;
}

void GetIpAddresses(LPSOCKADDR outGoing, LPSOCKADDR dnsServer1)
{
	ULONG size = 0;

	ULONG ret = GetAdaptersAddresses(AF_INET, GAA_FLAG_SKIP_DNS_SERVER | GAA_FLAG_INCLUDE_GATEWAYS, NULL, NULL, &size);

	IP_ADAPTER_ADDRESSES *addresses = (IP_ADAPTER_ADDRESSES*)malloc(size);

	ret = GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_GATEWAYS, NULL, addresses, &size);

	if (ret == ERROR_BUFFER_OVERFLOW || ret == ERROR_NOT_ENOUGH_MEMORY) {
		printf("Error %d\n", ret);
	}

	IP_ADAPTER_ADDRESSES* pCurrAddresses = addresses;

	PIP_ADAPTER_UNICAST_ADDRESS pUnicast = NULL;
	PIP_ADAPTER_ANYCAST_ADDRESS pAnycast = NULL;
	PIP_ADAPTER_MULTICAST_ADDRESS pMulticast = NULL;
	IP_ADAPTER_DNS_SERVER_ADDRESS* pDnServer = NULL;
	IP_ADAPTER_PREFIX* pPrefix = NULL;

	DWORD i;
	char name[80];
	while (pCurrAddresses) {

		pDnServer = pCurrAddresses->FirstDnsServerAddress;
		if (pDnServer && pCurrAddresses->OperStatus == IfOperStatusUp) {

			printf("\tLength of the IP_ADAPTER_ADDRESS struct: %ld\n",
				pCurrAddresses->Length);
			printf("\tIfIndex (IPv4 interface): %u\n", pCurrAddresses->IfIndex);
			printf("\tAdapter name: %s\n", pCurrAddresses->AdapterName);

			pUnicast = pCurrAddresses->FirstUnicastAddress;
			if (pUnicast != NULL) {
				*outGoing = *pCurrAddresses->FirstUnicastAddress->Address.lpSockaddr;
				for (i = 0; pUnicast != NULL; i++) {

					sockaddr_in* ipv4 = (sockaddr_in*)pUnicast->Address.lpSockaddr;
					PCSTR str = inet_ntop(ipv4->sin_family, &ipv4->sin_addr, name, sizeof(name));

					printf("\tUnicast IPv4 address %s\n", str);

					pUnicast = pUnicast->Next;
				}

				printf("\tNumber of Unicast Addresses: %d\n", i);
			}
			else
				printf("\tNo Unicast Addresses\n");

			pAnycast = pCurrAddresses->FirstAnycastAddress;
			if (pAnycast) {
				for (i = 0; pAnycast != NULL; i++)
				{

					pAnycast = pAnycast->Next;
				}
				printf("\tNumber of Anycast Addresses: %d\n", i);
			}
			else
				printf("\tNo Anycast Addresses\n");

			pMulticast = pCurrAddresses->FirstMulticastAddress;
			if (pMulticast) {
				for (i = 0; pMulticast != NULL; i++)
					pMulticast = pMulticast->Next;
				printf("\tNumber of Multicast Addresses: %d\n", i);
			}
			else
				printf("\tNo Multicast Addresses\n");

			pDnServer = pCurrAddresses->FirstDnsServerAddress;
			if (pDnServer && pCurrAddresses->FirstUnicastAddress) {
				*dnsServer1 = *pDnServer->Address.lpSockaddr;
				for (i = 0; pDnServer != NULL; i++) {

					sockaddr_in* ipv4 = (sockaddr_in*)(pDnServer->Address.lpSockaddr);
					PCSTR str = inet_ntop(ipv4->sin_family, &ipv4->sin_addr, name, sizeof(name));

					printf("\tDNS IPv4 address %s\n", str);

					pDnServer = pDnServer->Next;
				}
				printf("\tNumber of DNS Server Addresses: %d\n", i);
			}
			else
				printf("\tNo DNS Server Addresses\n");

			printf("\tDNS Suffix: %wS\n", pCurrAddresses->DnsSuffix);
			printf("\tDescription: %wS\n", pCurrAddresses->Description);
			printf("\tFriendly name: %wS\n", pCurrAddresses->FriendlyName);

			if (pCurrAddresses->PhysicalAddressLength != 0) {
				printf("\tPhysical address: ");
				for (i = 0; i < (int)pCurrAddresses->PhysicalAddressLength;
					i++) {
					if (i == (pCurrAddresses->PhysicalAddressLength - 1))
						printf("%.2X\n",
							(int)pCurrAddresses->PhysicalAddress[i]);
					else
						printf("%.2X-",
							(int)pCurrAddresses->PhysicalAddress[i]);
				}
			}
			printf("\tFlags: %ld\n", pCurrAddresses->Flags);
			printf("\tMtu: %lu\n", pCurrAddresses->Mtu);
			printf("\tIfType: %ld\n", pCurrAddresses->IfType);
			printf("\tOperStatus: %ld\n", pCurrAddresses->OperStatus);
			printf("\tIpv6IfIndex (IPv6 interface): %u\n",
				pCurrAddresses->Ipv6IfIndex);
			printf("\tZoneIndices (hex): ");
			for (i = 0; i < 16; i++)
				printf("%lx ", pCurrAddresses->ZoneIndices[i]);
			printf("\n");

			printf("\tTransmit link speed: %I64u\n", pCurrAddresses->TransmitLinkSpeed);
			printf("\tReceive link speed: %I64u\n", pCurrAddresses->ReceiveLinkSpeed);

			pPrefix = pCurrAddresses->FirstPrefix;
			if (pPrefix) {
				for (i = 0; pPrefix != NULL; i++)
					pPrefix = pPrefix->Next;
				printf("\tNumber of IP Adapter Prefix entries: %d\n", i);
			}
			else
				printf("\tNumber of IP Adapter Prefix entries: 0\n");

			printf("\n");
		}

		pCurrAddresses = pCurrAddresses->Next;
	}

	free(addresses);

}

int main() {


	/*
	WSADATA wsadata;

	int res;

	res = WSAStartup(MAKEWORD(2, 2), &wsadata);

	if (res)
	{
		printf("Cannot start up %d\n", res);
		return -1;
	}

	SOCKADDR result, dnsserver;

	GetIpAddresses(&result, &dnsserver);

	char name[80];
	sockaddr_in* sockin = (sockaddr_in*)&result;
	sockin->sin_port = htons(1901);

	PCSTR str = inet_ntop(sockin->sin_family, &sockin->sin_addr, name, sizeof(name));

	printf("\tIPv4 address %s\n", str);

	SOCKET ListenSocket = INVALID_SOCKET;

	ListenSocket = socket(sockin->sin_family, SOCK_STREAM, IPPROTO_TCP);

	if (ListenSocket == INVALID_SOCKET) {
		printf("Error at socket(): %ld\n", WSAGetLastError());
		WSACleanup();
		return -1;
	}


	res = bind(ListenSocket, &result, sizeof(result));

	if (res == SOCKET_ERROR) {
		printf("bind failed with error: %d\n", WSAGetLastError());
		closesocket(ListenSocket);
		WSACleanup();
		return -1;
	}

	res = 0;

	if (listen(ListenSocket, SOMAXCONN) == SOCKET_ERROR) {
		printf("Listen failed with error: %ld\n", WSAGetLastError());
		res = -1;
	}

	int receptionCount = 0;

	while (!res)
	{
		
		SOCKET *ClientSocket = &Clients[receptionCount];

		*ClientSocket = accept(ListenSocket, NULL, NULL);

		if (*ClientSocket == INVALID_SOCKET) {
			printf("accept failed: %d\n", WSAGetLastError());
			res = -1;
			continue;
		}

		ReceptionHandle[receptionCount] = CreateThreadOfFuncForThread(receptionCount);
		receptionCount++;
	}
	
	closesocket(ListenSocket);
	WSACleanup();

	return res;

	*/


	const char* fileRoot = "C:\\Users\\dflet\\Documents\\Visual Studio Projects\\Network\\named.root.txt";

	int ret = ParseNamedRoot(fileRoot);

	WSADATA wsadata;

	int res;

	res = WSAStartup(MAKEWORD(2, 2), &wsadata);

	if (res)
	{
		printf("Cannot start up %d\n", res);
		return -1;
	}

	SOCKADDR result, dnsserver;

	GetIpAddresses(&result, &dnsserver);

	int answerCount = 0;

	DNSQueryResult* ress = GetAddrByHostName((sockaddr_in*)&dnsserver, "www.google.com\0", NS, &answerCount);

	for (int i = 0; i < answerCount; i++)
	{
		printf("%d)\n", i + 1);
		ShowDNSQueryResult(&ress[i]);
		printf("---------------------------\n");
	}

	WSACleanup();

	return res;
}