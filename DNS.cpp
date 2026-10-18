#include "DNS.h"
#include "DNSRoots.h"

#include <stdio.h>
#include <ws2tcpip.h>
#include <sysinfoapi.h>
#include <stdlib.h>
#include <limits.h>

#define DEFAULT_DNS_PORT 53
#define CACHE_LINE  64
#define CACHE_ALIGN __declspec(align(CACHE_LINE))

#define MAX_USHORT ((uint16_t)~0)
#define MAX_UINT ((uint32_t)~0)

#define QUERYHOSTNAME MAX_USHORT

#define DNS_PARSED_ALIGNMENT alignof(void*)

#define ALIGN_PWR2(size, align) (((size) + (align)-1) & ~((align)-1))

#define ERROR_LOG_LVL 1
#define DEBUG_LOG_LVL 2
#define INFO_LOG_LVL 3

#define DNS_LOG_LVL 3

#define STRINGIFY_IMPL(X) #X
#define STRINGIFY(X) STRINGIFY_IMPL(X)

#define KB 1024
#define MB 1024 * KB
#define GB 1024 * MB

#define DNSANSPOOLSIZE 512*KB
#define DNSQUERYPOOLSIZE 256*KB
#define FUNCANSWEPOOL 2 * MB
#define RECORDPOOLSIZE 256*KB

#define MAX_RECURSE_LIMIT 10

#if defined(INFO_LOG_LVL) && DNS_LOG_LVL >= INFO_LOG_LVL
#define INFOLOG(fmt, ...) \
        (printf("INFO : %s " STRINGIFY(__LINE__) " : " fmt "\n", __FILE__,  ##__VA_ARGS__))
#else 
#define INFOLOG(fmt, ...)
#endif

#if defined(DEBUG_LOG_LVL) && DNS_LOG_LVL >= DEBUG_LOG_LVL
#define DEBUGLOG(fmt, ...)  \
        (printf("DEBUG : %s " STRINGIFY(__LINE__) " : " fmt "\n", __FILE__,  ##__VA_ARGS__))
#else
#define DEBUGLOG(fmt, ...)
#endif


#if  defined(ERROR_LOG_LVL) && DNS_LOG_LVL >= ERROR_LOG_LVL
#define ERRORLOG(fmt, ...) \
        (printf("ERROR : %s " STRINGIFY(__LINE__) " : " fmt "\n", __FILE__,  ##__VA_ARGS__))
#else
#define ERRORLOG(fmt, ...)
#endif

#define MAX_STRING_LEN 256
#define COPYSTRING(src, dest, count) \
	do { \
		dest[count] = src[count]; \
	} while(src[count++] && count < MAX_STRING_LEN) \

#define MAKE_NETWORK_USHORT_FROM_BYTES(ptr) (uint16_t)((((uint16_t)((ptr)[0]))<<8) | ((uint16_t)((ptr)[1])&0xff))
#define MAKE_NETWORK_UINT_FROM_BYTES(ptr) (uint32_t)((((uint32_t)((ptr)[0])&0xff)<<24) | \
													 (((uint32_t)((ptr)[1])&0xff)<<16) | \
													 (((uint32_t)((ptr)[2])&0xff)<<8) | \
													 ((uint32_t)((ptr)[3])&0xff))

enum DNSReturnCodes
{
	NODOMAIN = 0,
	SERVERFAILURE = -1,
};

enum DNSRDLengthExact
{
	RDLEN_A = 4,   
	RDLEN_AAAA = 16, 
};

typedef struct dns_answer_queryhostname {
	uint16_t arecordcount;
	uint16_t pad;
	uint32_t arecordid[10];
	uint32_t pad2;
} DNSQueryHostnameRecord;

typedef struct dns_record_reference
{
	uint16_t type;
	uint16_t offset;
	void* packet;
	uint32_t size;
	uint32_t pad;
} DNSRecordReference;

typedef struct dns_answer_a
{
	uint32_t referenceHostNameRecordID;
	uint32_t dnsAnswerHostRecordID;
	uint32_t addr;
	uint32_t pad;
} DNSARecord;

typedef struct dns_answer_aaaa
{
	uint32_t referenceHostNameRecordID;
	uint32_t dnsAnswerHostRecordID;
	char addr[16];
}DNSAAAARecord;

typedef struct dns_answer_cname {
	uint16_t namelength;
	uint16_t arecordcount;
	uint32_t arecordid[10];
	uint32_t queryAlias; //reference alias
	uint32_t cnameAlias; //reference to uncompressed name
	uint32_t pad;
} DNSCNAMERecord;

typedef struct dns_answer_ns {
	uint16_t namelength;
	uint16_t arecordcount;
	uint32_t arecordid[10];
	uint32_t queryAlias; //reference alias
	uint32_t cnameAlias; //reference to uncompressed name
	uint32_t pad;
} DNSNSRecord;

typedef struct dns_answer_mx {
	uint16_t preference;
	uint16_t namelength;
	uint16_t arecordcount;
	uint16_t pad;
	uint32_t arecordid[10];
	uint32_t queryAlias; //reference alias
	uint32_t cnameAlias; //reference to uncompressed name
} DNSMXRecord;

typedef struct dns_pointer_struct
{
	uint32_t recordOffset;
	uint32_t dnsReferenceRecordOffset;
	uint32_t internalRecordBufferOffset;
} DNSPointer;

typedef struct dns_fsm_t
{
	int lErrorCodes;
	int lDnsQueryCount;
	uint32_t lDnsQueryLength;
	uint32_t lAnswerProcessed; //amount being processed in the 
	uint32_t lAnswerCurrentSize; //amount that makes up current size;
	uint32_t lAnswerPoolHead; //current in answer pool 
	uint32_t lAnswerPoolAmount; //amount of data allocated from pool
	uint32_t lRecordBufferAmount;
	uint32_t lRecordBufferStart;
	uint32_t lRecordBufferHead;
	char* lQueryAnswerHead;
} DNSFSM;

static CACHE_ALIGN char QueryPool[DNSQUERYPOOLSIZE];
static int QueryCount = 0;
static CACHE_ALIGN char RawDNSAnswerPool[DNSANSPOOLSIZE];
static int RawDNSAnswerCount = 0;

static CACHE_ALIGN char RecordsBuffer[RECORDPOOLSIZE];
static uint32_t RecordsBufferCounter = 0;
static uint32_t RecordsBufferReader = 0;

static CACHE_ALIGN char HelperSpace[128];
static CACHE_ALIGN char FunctionAnswerPool[FUNCANSWEPOOL];
static int FunctionAnswerPtr = 0;

static CACHE_ALIGN int RecursionLevelPointers[MAX_RECURSE_LIMIT];
static CACHE_ALIGN int RecursionLevelEnds[MAX_RECURSE_LIMIT];
static int RecursionLevelPointer = 0;

static uint16_t MakeDNSFlags(int QR, int OpCode, int AA, int TC, int RD, int RA, int Z, int RCODE)
{
	uint16_t ret = 0;

	ret =
		(QR & 1) << 15 |
		(OpCode & 0xf) << 11 |
		(AA & 1) << 10 |
		(TC & 1) << 9 |
		(RD & 1) << 8 |
		(RA & 1) << 7 |
		(Z & 7) << 4 |
		(RCODE & 0xf) << 0;

	return ret;
}

static void PrintDNSFlags(uint16_t flags)
{
	DEBUGLOG("QR=%d ", (flags >> 15) & 0x1);
	DEBUGLOG("OpCode=%d ", (flags >> 11) & 0xF);
	DEBUGLOG("AA=%d ", (flags >> 10) & 0x1);
	DEBUGLOG("TC=%d ", (flags >> 9) & 0x1);
	DEBUGLOG("RD=%d ", (flags >> 8) & 0x1);
	DEBUGLOG("RA=%d ", (flags >> 7) & 0x1);
	DEBUGLOG("Z=%d ", (flags >> 4) & 0x7);
	DEBUGLOG("RCODE=%d", (flags >> 0) & 0xF);
}

static int CreateQueryHostname(const char* hostname, char* output)
{
	int stride = 0;

	if (!hostname || !output)
		return stride;
	
	const char* ptr = hostname;
	char* outputAddr = output;

	while (*ptr)
	{
		char count = 0;
		char* insertCount = outputAddr;
		outputAddr++;
		while (*ptr != '.' && *ptr != '\0')
		{
			*outputAddr = *ptr;
			count++;
			ptr++;
			outputAddr++;
		}
		
		if (count) 
		{
			ptr++;
			*insertCount = count;
			stride += (count + 1);
		}
	}

	*outputAddr = 0;

	return stride + 1;
};

static int dumpstring(char* c, char count, int terminate)
{
#if DNS_LOG_LVL >= 2
	int i = 0;
	while (count-- > 0)
	{
		printf("%c", *c);
		c++;
		i++;
		if (!count && terminate > 0) 
		{
			printf(".");
		}
	} 
	return i;
#else
	return 0;
#endif
}

static int writestring(char* c, char count, int terminate, char *write)
{
	int i = 0;

	while (count-- > 0)
	{
		*write++ = *c++;
		i++;
	}

	char finalChar = '\0';
	
	if (terminate) 
	{
		finalChar = '.';
	}

	*write++ = finalChar;
	i++;

	return i;
}

static int WriteHostName(DNSFSM* fsmPtr, char* outWrite);
static int PrintHostName(DNSFSM* fsmPtr);
static void HandlePointerCondition(DNSFSM* fsm, DNSPointer* pointer);
static int HandleDNSAnswer(DNSFSM* fsm, DNSAnswer* answer, DNSPointer* pointer);
static int CreateAnswers(DNSFSM* fsmPtr, DNSQueryResult* resultSpace);
static void PrintIPv4(uint32_t addr);
static void PrintIPv6(char* addr);
static void PrintRecordHostname(char* ptr);
static int DeDeuplicateIPv4(char* recordBuffer, uint16_t count, uint32_t* recordoffsets, int addr);
static int DeDeuplicateIPv6(char* recordBuffer, uint16_t count, uint32_t* recordoffsets, char* addr);
static int ProcessRawRecordsBuffer(DNSFSM* fsmPtr);
static void CreateDNSHeaderFromNetworkBytes(DNSHeader* header, DNSFSM* fsm);
static void CreateDNSAnswerFromNetworkBytes(DNSAnswer* answer, DNSFSM* fsm);
static void CreateDNSSOARecordFromNetworkBytes(DNSSOA* soa, DNSFSM* fsm);

static int RecurseFindAddress(int* recordPtr)
{
	int addr = 0, begin = *recordPtr;

	DNSRecordReference* ref = (DNSRecordReference*)&RecordsBuffer[begin];
	switch (ref->type)
	{
	case A:
	{
		DNSARecord* record = (DNSARecord*)&RecordsBuffer[begin + sizeof(DNSRecordReference)];

		addr = record->addr;

		break;
	}
	case CNAME:
	{
		DNSCNAMERecord* record = (DNSCNAMERecord*)&RecordsBuffer[begin + sizeof(DNSRecordReference)];

		if (record->arecordcount)
		{
			for (uint16_t g = 0; g < record->arecordcount; g++)
			{
				DNSRecordReference* aRef1 = (DNSRecordReference*)&RecordsBuffer[record->arecordid[g]];

				DNSARecord* aRef = (DNSARecord*)&RecordsBuffer[record->arecordid[g] + sizeof(DNSRecordReference)];

				addr = aRef->addr;

				goto recurse_find_end;
			}
		}
		else 
		{
			addr = -1;
		}

		break;
	}
	case NS:
	{
		DNSNSRecord* record = (DNSNSRecord*)&RecordsBuffer[begin + sizeof(DNSRecordReference)];

		if (record->arecordcount)
		{
			for (uint16_t g = 0; g < record->arecordcount; g++)
			{
				DNSRecordReference* aRef1 = (DNSRecordReference*)&RecordsBuffer[record->arecordid[g]];

				if (aRef1->type == A)
				{
					DNSARecord* aRef = (DNSARecord*)&RecordsBuffer[record->arecordid[g] + sizeof(DNSRecordReference)];

					addr = aRef->addr;

					goto recurse_find_end;
				}
			}	
		}
		else // need to search for name
		{
			addr = -1;
		}

		break;
	}
	case MX:
	{

		DNSMXRecord* record = (DNSMXRecord*)&RecordsBuffer[begin + sizeof(DNSRecordReference)];

		if (record->arecordcount)
		{
			for (uint16_t g = 0; g < record->arecordcount; g++)
			{
				DNSRecordReference* aRef1 = (DNSRecordReference*)&RecordsBuffer[record->arecordid[g]];

				if (aRef1->type == A)
				{
					DNSARecord* aRef = (DNSARecord*)&RecordsBuffer[record->arecordid[g] + sizeof(DNSRecordReference)];

					addr = aRef->addr;

					goto recurse_find_end;
				}
			}
		}

		break;
	}
	default:
		break;
	}

recurse_find_end:

	if (!addr) *recordPtr += ref->size;

	return addr;
}


static int RecurseDNSResolver(sockaddr_in* dnsResolver, DNSFSM* dnsFSM)
{
	int addr = 0;
	int begin = dnsFSM->lRecordBufferStart;
	/*
	if (RecursionLevelPointer+1 < MAX_RECURSE_LIMIT && dnsFSM->lRecordBufferStart < dnsFSM->lRecordBufferPtr) // we have new records
	{
		if (RecursionLevelPointers[++RecursionLevelPointer] == -1)
		{
			while (!addr && begin < dnsFSM->lRecordBufferPtr)
			{
				addr = RecurseFindAddress(&begin);	
			}
		}
	}
	
	if (!addr)
	{

		RecursionLevelPointer--;
		

		while (!addr && RecursionLevelPointer >= 0)
		{

			begin = RecursionLevelPointers[RecursionLevelPointer]; // got a new level;

			addr = RecurseFindAddress(&begin);

			if (!addr)
			{
		
				if (begin == RecursionLevelEnds[RecursionLevelPointer])
				{
					RecursionLevelPointers[RecursionLevelPointer] = -1;
					RecursionLevelPointer--;
				}
				else 
				{
					RecursionLevelPointers[RecursionLevelPointer] = begin;
				}
			}
		}
	}
	else 
	{
		// got a new level;
		RecursionLevelEnds[RecursionLevelPointer] = dnsFSM->lRecordBufferPtr;
		RecursionLevelPointers[RecursionLevelPointer] = begin;
	}

	dnsFSM->lRecordBufferReader = dnsFSM->lRecordBufferPtr;

	PrintIPv4(addr);

	dnsResolver->sin_addr.s_addr = (addr);

	return (addr ? 0 : -1);
	*/

	return -1;
}

static int CreateDNSQuestion(int flags, const char* domainname, int queryCount)
{
	char* q = QueryPool + queryCount;

	DNSHeader* header = (DNSHeader*)q;
	memset(header, '\0', sizeof(DNSHeader));

	header->flags = htons(MakeDNSFlags(0, 0, 0, 0, 0, 0, 0, 0));
	header->QDCOUNT = htons(1);
	header->ID = htons(rand() % USHRT_MAX);

	int QuestionStride = CreateQueryHostname(domainname, q + sizeof(DNSHeader));

	DNSQuestion* question = (DNSQuestion*)(q + QuestionStride + sizeof(DNSHeader));

	question->QTYPE = htons(flags);
	question->QCLASS = htons(1);

	int currLength = QuestionStride + sizeof(DNSHeader) + sizeof(DNSQuestion);

	return currLength;
}

static int AskDNSQuestionAndHandleResponse(sockaddr_in* dnsServer, DNSFSM *dnsFSM, int* lErrorReturn)
{
	PCSTR IPv4Decode = inet_ntop(dnsServer->sin_family, &dnsServer->sin_addr, HelperSpace, sizeof(HelperSpace));

	DEBUGLOG("Searching in IPv4 address %s", IPv4Decode);

	DNSHeader* header = (DNSHeader*)(QueryPool + dnsFSM->lDnsQueryCount);

	SOCKET ConnectionSocket = INVALID_SOCKET;

	ConnectionSocket = socket(dnsServer->sin_family, SOCK_DGRAM, IPPROTO_UDP);

	if (INVALID_SOCKET == ConnectionSocket)
	{
		DEBUGLOG("Error at socket(): %ld", WSAGetLastError());
		return -1;
	}

	int res = connect(ConnectionSocket, ((sockaddr*)dnsServer), sizeof(sockaddr_in));

	if (SOCKET_ERROR == res)
	{
		closesocket(ConnectionSocket);
		return -1;
	}

	res = send(ConnectionSocket, (char*)header, dnsFSM->lDnsQueryLength, 0);

	if (SOCKET_ERROR == res)
	{
		DEBUGLOG("send failed with error: %d", WSAGetLastError());
		closesocket(ConnectionSocket);
		return -1;
	}

	DEBUGLOG("Bytes sent %ld", res);

	res = recv(ConnectionSocket, RawDNSAnswerPool + dnsFSM->lAnswerPoolHead, dnsFSM->lAnswerPoolAmount - dnsFSM->lAnswerPoolHead, 0);

	if (res > 0) 
	{
		DEBUGLOG("Bytes received: %d", res);
	}
	else if (!res)
		DEBUGLOG("Connection closed");
	else
		DEBUGLOG("recv failed with error: %d", WSAGetLastError());

	closesocket(ConnectionSocket);

	dnsFSM->lAnswerCurrentSize = res;
	dnsFSM->lAnswerProcessed = 0;
	dnsFSM->lQueryAnswerHead = (RawDNSAnswerPool + dnsFSM->lAnswerPoolHead);

	int found = 0;

	DNSHeader headera;

	CreateDNSHeaderFromNetworkBytes(&headera, dnsFSM);

	DEBUGLOG("Header ID: %hx", headera.ID);
	DEBUGLOG("flags ID: %hx", headera.flags);
	PrintDNSFlags(headera.flags);
	DEBUGLOG("QDCOUNT ID: %hx", headera.QDCOUNT);
	DEBUGLOG("ANCOUNT ID: %hx", headera.ANCOUNT);
	DEBUGLOG("NSCOUNT ID: %hx", headera.NSCOUNT);
	DEBUGLOG("ARCOUNT ID: %hx", headera.ARCOUNT);

	int ret = PrintHostName(dnsFSM);

	uint16_t rcode = headera.flags & 0xf;

	uint16_t anCount = headera.ANCOUNT;

	uint16_t nDomainCount = headera.NSCOUNT;

	uint16_t adRecordCount = headera.ARCOUNT;

	if (rcode == RCODE_NOERROR && anCount >= 1)
		found = 1;

	if (rcode == RCODE_SERVFAIL || rcode == RCODE_NOTIMPLEMENTED)
	{
		*lErrorReturn = SERVERFAILURE;
		return found;
	}

	if (rcode == RCODE_NXDOMAIN) 
	{
		found = 1;
		if (!nDomainCount)
		{
			return found;
		}
	}

	DNSRecordReference* ref = (DNSRecordReference*)&RecordsBuffer[dnsFSM->lRecordBufferHead];
	ref->packet = (void*)dnsFSM->lQueryAnswerHead;
	ref->offset = dnsFSM->lAnswerProcessed;
	ref->type = QUERYHOSTNAME;
	ref->size = sizeof(DNSRecordReference) + sizeof(DNSQueryHostnameRecord);

	dnsFSM->lRecordBufferHead += sizeof(DNSRecordReference);

	DNSQueryHostnameRecord* queryHostnameRecord = (DNSQueryHostnameRecord*)&RecordsBuffer[dnsFSM->lRecordBufferHead];

	queryHostnameRecord->arecordcount = 0;

	dnsFSM->lRecordBufferHead += sizeof(DNSQueryHostnameRecord);

	int writeName = WriteHostName(dnsFSM, &RecordsBuffer[dnsFSM->lRecordBufferHead]);

	dnsFSM->lAnswerProcessed += sizeof(DNSQuestion);

	writeName = ALIGN_PWR2(writeName, DNS_PARSED_ALIGNMENT);

	ref->size += writeName;

	dnsFSM->lRecordBufferHead += writeName;

	uint16_t parseCounts[3] = { anCount, nDomainCount, adRecordCount };

	for (uint16_t iter = 0; iter < 3; iter++)
	{
		for (uint16_t counter = 0; counter < parseCounts[iter]; counter++)
		{
			DNSPointer dnsPointer =
			{
				MAX_UINT, MAX_UINT, MAX_UINT
			};

			HandlePointerCondition(dnsFSM, &dnsPointer);

			DNSAnswer answer;

			CreateDNSAnswerFromNetworkBytes(&answer, dnsFSM);

			dnsPointer.recordOffset = dnsFSM->lAnswerProcessed;

			HandleDNSAnswer(dnsFSM, &answer, &dnsPointer);
		}
	}

	ProcessRawRecordsBuffer(dnsFSM);

	dnsFSM->lDnsQueryCount += dnsFSM->lDnsQueryLength;
	dnsFSM->lAnswerPoolHead += dnsFSM->lAnswerCurrentSize;

	dnsFSM->lAnswerCurrentSize = 0;
	dnsFSM->lAnswerProcessed = 0;
	dnsFSM->lDnsQueryLength = 0;
	
	*lErrorReturn = anCount;

	return found;
}

DNSQueryResult* GetAddrByHostName(sockaddr_in *s, const char* str, int flags, int* answerCount)
{
	if (!s || !str) return NULL;

	if (s->sin_family != AF_INET)
	{
		ERRORLOG("Only IPv4 addresses to use for inital dns");
		return NULL;
	}

	srand(GetTickCount());

	sockaddr_in dnsResolver;

	dnsResolver.sin_addr = s->sin_addr;
	dnsResolver.sin_family = s->sin_family;
	dnsResolver.sin_port = htons(DEFAULT_DNS_PORT);

	int found = 0;

	int lErrorReturn = NODOMAIN;

	int recursed = 0;

	memset(RecursionLevelPointers, 0xFF, sizeof(RecursionLevelPointers));
	RecursionLevelPointer = -1;

	DNSFSM fsm;
	
	memset(&fsm, 0, sizeof(DNSFSM));

	fsm.lAnswerPoolAmount = sizeof(RawDNSAnswerPool);
	fsm.lRecordBufferAmount = sizeof(RecordsBuffer);
	fsm.lDnsQueryCount = QueryCount;
	
	do
	{
		int currLength = CreateDNSQuestion(flags, str, fsm.lDnsQueryCount);

		fsm.lDnsQueryLength = currLength;

		found = AskDNSQuestionAndHandleResponse(&dnsResolver, &fsm, &lErrorReturn);

		if (!found || RecursionLevelPointer >= 0)
		{
			found = RecurseDNSResolver(&dnsResolver, &fsm);
		}

	} while (!found);

	DNSQueryResult* returnHeader = (DNSQueryResult*)&FunctionAnswerPool[FunctionAnswerPtr];

	if (lErrorReturn > 0) 
	{
		int ResultCount = CreateAnswers(&fsm, returnHeader);

		*answerCount = ResultCount;
	}
	else 
	{
		*answerCount = lErrorReturn;
	}

	RawDNSAnswerCount = 0;
	QueryCount = 0;
	RecordsBufferCounter = 0;
	RecordsBufferReader = 0;

	return returnHeader;
}

int DeDeuplicateIPv4(char* recordBuffer, uint16_t count, uint32_t* recordoffsets, int addr)
{
	int dup = 0;
	for (uint16_t i = 0; i < count; i++)
	{
		DNSRecordReference* aRef1 = (DNSRecordReference*)&recordBuffer[recordoffsets[i]];
		if (aRef1->type == A)
		{
			DNSARecord* aRef = (DNSARecord*)&recordBuffer[recordoffsets[i] + sizeof(DNSRecordReference)];

			int lAddr = aRef->addr;

			if (addr == lAddr)
			{
				dup = 1;
				break;
			}
		}
	}

	return dup;
}

int DeDeuplicateIPv6(char* recordBuffer, uint16_t count, uint32_t *recordoffsets, char* addr)
{
	int dup = 0;

	for (uint16_t i = 0; i < count; i++)
	{
		DNSRecordReference* aRef1 = (DNSRecordReference*)&recordBuffer[recordoffsets[i]];
		if (aRef1->type == AAAA)
		{
			DNSAAAARecord* aRef = (DNSAAAARecord*)&recordBuffer[recordoffsets[i] + sizeof(DNSRecordReference)];

			if (!memcmp(aRef->addr, addr, 16))
			{
				dup = 1;
				break;
			}
		}
	}

	return dup;
}

int CreateAnswers(DNSFSM* fsmPtr, DNSQueryResult* resultSpace)
{
	int ResultCount = 0;
	DNSQueryResult* resultPtr = resultSpace;
	for (uint32_t j = fsmPtr->lRecordBufferStart; j < fsmPtr->lRecordBufferHead;) 
	{
		DNSRecordReference* ref = (DNSRecordReference*)&RecordsBuffer[j];

		memset(resultPtr, 0, sizeof(DNSQueryResult));

		switch (ref->type)
		{
		case QUERYHOSTNAME:
		{
			DNSQueryHostnameRecord* record = (DNSQueryHostnameRecord*)&RecordsBuffer[j + sizeof(DNSRecordReference)];
			char* ptr = (char*)(record + 1);

			DEBUGLOG("Hostname : ");
			PrintRecordHostname(ptr);

			memset(resultPtr->hostname, 0, sizeof(resultPtr->hostname));

			int hostNameCount = 0;

			COPYSTRING(ptr, resultPtr->hostname, hostNameCount);

			int aliasNameCount = 0;

			if (record->arecordcount)
			{
				for (uint16_t g = 0; g < record->arecordcount; g++)
				{
					DNSRecordReference* aRef1 = (DNSRecordReference*)&RecordsBuffer[record->arecordid[g]];

					if (aRef1->type == A)
					{
						DNSARecord* aRef = (DNSARecord*)&RecordsBuffer[record->arecordid[g] + sizeof(DNSRecordReference)];

						uint32_t addr = aRef->addr;

						if (DeDeuplicateIPv4(RecordsBuffer, g, record->arecordid, addr))
						{
							continue;
						}

						resultPtr->ipv4or6 = A;
						resultPtr->ipv4 = addr;
						PrintIPv4(addr);
					}
					else if (aRef1->type == AAAA)
					{
						DNSAAAARecord* aRef = (DNSAAAARecord*)&RecordsBuffer[record->arecordid[g] + sizeof(DNSRecordReference)];

						if (DeDeuplicateIPv6(RecordsBuffer, g, record->arecordid, aRef->addr))
						{
							continue;
						}

						PrintIPv6(aRef->addr);
						resultPtr->ipv4or6 = AAAA;
						memcpy(resultPtr->ipv6, aRef->addr, 16);
					}

					DNSQueryResult* prev = resultPtr;

					resultPtr++;
					ResultCount++;

					memset(resultPtr, 0, sizeof(DNSQueryResult));

					memcpy(resultPtr->aliasname, prev->aliasname, aliasNameCount);
					memcpy(resultPtr->hostname, prev->hostname, hostNameCount);
				}
			}
	
			break;
		}
		case CNAME:
		{
			DNSCNAMERecord* record = (DNSCNAMERecord*)&RecordsBuffer[j + sizeof(DNSRecordReference)];
			char* ptr = (char*)&RecordsBuffer[j + sizeof(DNSRecordReference) + sizeof(DNSCNAMERecord)];
			DEBUGLOG("Hostname : ");
			PrintRecordHostname(ptr);

			memset(resultPtr->hostname, 0, sizeof(resultPtr->hostname));
			int hostNameCount = 0;
			COPYSTRING(ptr, resultPtr->hostname, hostNameCount);

			int aliasNameCount = 0;

			if (record->queryAlias != MAX_USHORT)
			{
				DNSRecordReference* aRef1 = (DNSRecordReference*)&RecordsBuffer[record->queryAlias];

				char* ptr = NULL;

				int off = 0;

				if (aRef1->type == QUERYHOSTNAME)
				{
					off = sizeof(DNSRecordReference);

				}
				else if (aRef1->type == CNAME)
				{
					off = sizeof(DNSRecordReference) + sizeof(DNSCNAMERecord);
				}

				ptr = (char*)&RecordsBuffer[record->queryAlias + off];
				
				DEBUGLOG("Alias Hostname : ");
				PrintRecordHostname(ptr);

				COPYSTRING(ptr, resultPtr->aliasname, aliasNameCount);
			}

			if (record->arecordcount)
			{
				for (uint16_t g = 0; g < record->arecordcount; g++)
				{
					DNSRecordReference* aRef1 = (DNSRecordReference*)&RecordsBuffer[record->arecordid[g]];

					DNSARecord* aRef = (DNSARecord*)&RecordsBuffer[record->arecordid[g] + sizeof(DNSRecordReference)];

					uint32_t addr = aRef->addr;

					if (DeDeuplicateIPv4(RecordsBuffer, g, record->arecordid, addr))
					{
						continue;
					}

					PrintIPv4(addr);

					resultPtr->ipv4or6 = A;
					resultPtr->ipv4 = addr;

					DNSQueryResult* prev = resultPtr;
					resultPtr++;
					ResultCount++;
					memset(resultPtr, 0, sizeof(DNSQueryResult));

					memcpy(resultPtr->aliasname, prev->aliasname, aliasNameCount);
					memcpy(resultPtr->hostname, prev->hostname, hostNameCount);
				}
			}
			break;
		}
		case NS:
		{
			DNSNSRecord* record = (DNSNSRecord*)&RecordsBuffer[j + sizeof(DNSRecordReference)];
			char* ptr = (char*)&RecordsBuffer[j + sizeof(DNSRecordReference) + sizeof(DNSNSRecord)];
			DEBUGLOG("Hostname : ");
			PrintRecordHostname(ptr);

			memset(resultPtr->hostname, 0, sizeof(resultPtr->hostname));
			int hostNameCount = 0;
			COPYSTRING(ptr, resultPtr->hostname, hostNameCount);

			int aliasNameCount = 0;

			if (record->queryAlias != MAX_USHORT)
			{
				DNSRecordReference* aRef1 = (DNSRecordReference*)&RecordsBuffer[record->queryAlias];

				char* ptr = NULL;

				int off = 0;

				if (aRef1->type == QUERYHOSTNAME)
				{
					off = sizeof(DNSRecordReference);
				}

				ptr = (char*)&RecordsBuffer[record->queryAlias + off];
				DEBUGLOG("Alias Hostname : ");
				PrintRecordHostname(ptr);

				COPYSTRING(ptr, resultPtr->aliasname, aliasNameCount);
			}

			if (record->arecordcount)
			{
				for (uint16_t g = 0; g < record->arecordcount; g++)
				{
					DNSRecordReference* aRef1 = (DNSRecordReference*)&RecordsBuffer[record->arecordid[g]];

					if (aRef1->type == A)
					{
						DNSARecord* aRef = (DNSARecord*)&RecordsBuffer[record->arecordid[g] + sizeof(DNSRecordReference)];

						uint32_t addr = aRef->addr;

						if (DeDeuplicateIPv4(RecordsBuffer, g, record->arecordid, addr))
						{
							continue;
						}

						resultPtr->ipv4or6 = A;
						resultPtr->ipv4 = addr;
						PrintIPv4(addr);
					}
					else if (aRef1->type == AAAA)
					{
						DNSAAAARecord* aRef = (DNSAAAARecord*)&RecordsBuffer[record->arecordid[g] + sizeof(DNSRecordReference)];

						if (DeDeuplicateIPv6(RecordsBuffer, g, record->arecordid, aRef->addr))
						{
							continue;
						}

						PrintIPv6(aRef->addr);
						resultPtr->ipv4or6 = AAAA;
						memcpy(resultPtr->ipv6, aRef->addr, 16);
					}

					DNSQueryResult* prev = resultPtr;
					resultPtr++;
					ResultCount++;
					memset(resultPtr, 0, sizeof(DNSQueryResult));

					memcpy(resultPtr->aliasname, prev->aliasname, aliasNameCount);
					memcpy(resultPtr->hostname, prev->hostname, hostNameCount);
				}
			}
		}
		case MX:
		{
			DNSMXRecord* record = (DNSMXRecord*)&RecordsBuffer[j + sizeof(DNSRecordReference)];
			char* ptr = (char*)(record + 1);

			DEBUGLOG("Hostname : ");
			PrintRecordHostname(ptr);

			memset(resultPtr->hostname, 0, sizeof(resultPtr->hostname));

			int hostNameCount = 0;

			COPYSTRING(ptr, resultPtr->hostname, hostNameCount);

			int aliasNameCount = 0;

			if (record->queryAlias != MAX_USHORT)
			{
				DNSRecordReference* aRef1 = (DNSRecordReference*)&RecordsBuffer[record->queryAlias];

				int off = 0;

				if (aRef1->type == QUERYHOSTNAME)
				{
					off = sizeof(DNSRecordReference);
				}

				char* ptr = (char*)&RecordsBuffer[record->queryAlias + off];
				
				DEBUGLOG("Alias Hostname : ");
				
				PrintRecordHostname(ptr);

				COPYSTRING(ptr, resultPtr->aliasname, aliasNameCount);
			}

			if (record->arecordcount)
			{
				for (uint16_t g = 0; g < record->arecordcount; g++)
				{
					DNSRecordReference* aRef1 = (DNSRecordReference*)&RecordsBuffer[record->arecordid[g]];

					if (aRef1->type == A)
					{
						DNSARecord* aRef = (DNSARecord*)&RecordsBuffer[record->arecordid[g] + sizeof(DNSRecordReference)];

						uint32_t addr = aRef->addr;

						if (DeDeuplicateIPv4(RecordsBuffer, g, record->arecordid, addr))
						{
							continue;
						}

						resultPtr->ipv4or6 = A;
						resultPtr->ipv4 = addr;
						PrintIPv4(addr);
					}
					else if (aRef1->type == AAAA)
					{
						DNSAAAARecord* aRef = (DNSAAAARecord*)&RecordsBuffer[record->arecordid[g] + sizeof(DNSRecordReference)];

						if (DeDeuplicateIPv6(RecordsBuffer, g, record->arecordid, aRef->addr))
						{
							continue;
						}

						PrintIPv6(aRef->addr);
						resultPtr->ipv4or6 = AAAA;
						memcpy(resultPtr->ipv6, aRef->addr, 16);
					}

					DNSQueryResult* prev = resultPtr;
					
					resultPtr++;
					ResultCount++;
					
					memset(resultPtr, 0, sizeof(DNSQueryResult));

					memcpy(resultPtr->aliasname, prev->aliasname, aliasNameCount);
					memcpy(resultPtr->hostname, prev->hostname, hostNameCount);
				}
			}
			break;
		}
		}
		j += ref->size;

	}

	fsmPtr->lRecordBufferStart = fsmPtr->lRecordBufferHead;

	return ResultCount;
}

void ShowDNSQueryResult(DNSQueryResult* result)
{
	printf("%s\n", result->hostname);
	printf("%s\n", result->aliasname);
	if (result->ipv4or6 == A)
	{
		int addr = result->ipv4;
		printf("IPv4 Address is : \n");
		for (int i = 0; i < 3; i++)
		{
			printf("%d.", ((addr & 0xff000000) >> 24));
			addr <<= 8;
		}
		printf("%d\n", ((addr & 0xff000000) >> 24));
	}
	else if (result->ipv4or6 == AAAA) {

		printf("IPv6 Address is : \n");
		char* addr = result->ipv6;
		for (int i = 15; i > 0; i -= 4)
		{
			for (int j = 0; j < 4 && (i - j) >= 1; j++)
			{
				printf("%x", (unsigned char)addr[i-j]);
			}
			if (i > 4) printf(".");
		}
		printf("%x\n", addr[0]);
	}
}

void PrintRecordHostname(char* ptr)
{
#if DNS_LOG_LVL > 2
	while(*ptr)
	{
		printf("%c", *ptr++);
	}
	printf("\n");
#endif
}

void PrintIPv4(uint32_t addr)
{
#if DNS_LOG_LVL > 2
	DEBUGLOG("Address is : ");
	for (int i = 0; i < 3; i++)
	{
		printf("%d.", ((addr & 0xff000000) >> 24));
		addr <<= 8;
	}
	printf("%d\n", ((addr & 0xff000000) >> 24));
#endif
}

void PrintIPv6(char* addr)
{
#if DNS_LOG_LVL > 2
	DEBUGLOG("Address is : ");
	for (int i = 15; i > 0; i-=4)
	{
		for (int j = 0; j < 4 && (i - j) >= 1; j++)
		{
			printf("%x", addr[j]);
		}
		if (i > 4) printf(".");
	}
	printf("%x\n", addr[0]);
#endif
}

void HandlePointerCondition(DNSFSM* fsm, DNSPointer* pointer)
{
	uint16_t posPointer = MAKE_NETWORK_USHORT_FROM_BYTES(fsm->lQueryAnswerHead + fsm->lAnswerProcessed);

	if ((posPointer & 0xC000) == 0xC000)
	{
		posPointer &= 0x3fff;

		for (uint32_t j = fsm->lRecordBufferStart, i = 0; j < fsm->lRecordBufferHead; i++)
		{
			DNSRecordReference* ref = (DNSRecordReference*)&RecordsBuffer[j];
			
			if (ref->offset == posPointer)
			{
				DEBUGLOG("This is a reference to the %d response", i+1);
				pointer->internalRecordBufferOffset = j;
				break;
			}

			j += ref->size;
		}

		pointer->dnsReferenceRecordOffset = posPointer;

		fsm->lAnswerProcessed += 2;
	}
}

int HandleDNSAnswer(DNSFSM* fsm, DNSAnswer* answer, DNSPointer* pointer)
{
	DEBUGLOG("Type %hx", answer->TYPE);
	DEBUGLOG("Class %hx", answer->CLASS);
	DEBUGLOG("TTL %lx", answer->TTL);
	DEBUGLOG("RDLENGTH %hx", answer->RDLENGTH);

	uint32_t startReference = fsm->lRecordBufferHead;

	DNSRecordReference* ref = (DNSRecordReference*)&RecordsBuffer[fsm->lRecordBufferHead];
	ref->packet = (void*)fsm->lQueryAnswerHead;
	ref->offset = pointer->recordOffset;
	ref->type = answer->TYPE;

	int len = answer->RDLENGTH;

	switch (ref->type)
	{
	case A:
	{
		if (len != RDLEN_A)
		{
			ERRORLOG("DNS Answer: A record is not matching RDLEN: size %d, expected %d\n", len, RDLEN_A);
			break;
		}

		fsm->lRecordBufferHead += sizeof(DNSRecordReference);

		DNSARecord* record = (DNSARecord*)&RecordsBuffer[fsm->lRecordBufferHead];

		fsm->lRecordBufferHead += sizeof(DNSARecord);

		uint32_t addr = 0;
		for (int i = 0; i < len - 1; i++)
		{
			addr |= ((fsm->lQueryAnswerHead + fsm->lAnswerProcessed)[i] & 0xff);
			addr <<= 8;
		}
		addr |= ((fsm->lQueryAnswerHead + fsm->lAnswerProcessed)[3] & 0xff);

		record->addr = addr;
		record->referenceHostNameRecordID = pointer->internalRecordBufferOffset;
		record->dnsAnswerHostRecordID = pointer->dnsReferenceRecordOffset;
		PrintIPv4(addr);

		fsm->lAnswerProcessed += len;
		
		break;
	}
	case AAAA:
	{
		if (len != RDLEN_AAAA)
		{
			ERRORLOG("DNS Additional: AAAA record is not matching RDLEN: size %d, expected %d\n", len, RDLEN_AAAA);
			break;
		}

		fsm->lRecordBufferHead += sizeof(DNSRecordReference);

		DNSAAAARecord* record = (DNSAAAARecord*)&RecordsBuffer[fsm->lRecordBufferHead];

		fsm->lRecordBufferHead += sizeof(DNSAAAARecord);

		record->referenceHostNameRecordID = pointer->internalRecordBufferOffset;
		record->dnsAnswerHostRecordID = pointer->dnsReferenceRecordOffset;

		for (int i = 0; i < len; i++)
		{
			record->addr[15 - i] = ((fsm->lQueryAnswerHead + fsm->lAnswerProcessed)[i] & 0xff);
		}

		PrintIPv6(record->addr);

		fsm->lAnswerProcessed += len;

		break;
	}
	case CNAME:
	{
		PrintHostName(fsm);

		fsm->lRecordBufferHead += sizeof(DNSRecordReference);
		
		DNSCNAMERecord* record = (DNSCNAMERecord*)&RecordsBuffer[fsm->lRecordBufferHead];

		fsm->lRecordBufferHead += sizeof(DNSCNAMERecord);
		
		record->namelength = WriteHostName(fsm,  &RecordsBuffer[fsm->lRecordBufferHead]);
		record->arecordcount = 0;	
		record->queryAlias = pointer->internalRecordBufferOffset;
		record->cnameAlias = pointer->dnsReferenceRecordOffset;

		fsm->lRecordBufferHead += ALIGN_PWR2(record->namelength, DNS_PARSED_ALIGNMENT);

		break;
	}
	case NS:
	{
		PrintHostName(fsm);

		fsm->lRecordBufferHead += sizeof(DNSRecordReference);
		
		DNSNSRecord* record = (DNSNSRecord*)&RecordsBuffer[fsm->lRecordBufferHead];

		fsm->lRecordBufferHead += sizeof(DNSNSRecord);
		
		record->namelength = WriteHostName(fsm, &RecordsBuffer[fsm->lRecordBufferHead]);
		record->arecordcount = 0;
		record->queryAlias = pointer->internalRecordBufferOffset;
		record->cnameAlias = pointer->dnsReferenceRecordOffset;

		fsm->lRecordBufferHead += ALIGN_PWR2(record->namelength, DNS_PARSED_ALIGNMENT);

		break;
	}
	case MX:
	{
		fsm->lRecordBufferHead += sizeof(DNSRecordReference);
		
		uint16_t preference = MAKE_NETWORK_USHORT_FROM_BYTES((fsm->lQueryAnswerHead + fsm->lAnswerProcessed));

		fsm->lAnswerProcessed += 2;
		
		PrintHostName(fsm);

		DNSMXRecord* record = (DNSMXRecord*)&RecordsBuffer[fsm->lRecordBufferHead];

		fsm->lRecordBufferHead += sizeof(DNSMXRecord);

		record->preference = preference;
		record->arecordcount = 0;
		record->queryAlias = pointer->internalRecordBufferOffset;
		record->cnameAlias = pointer->dnsReferenceRecordOffset;

		record->namelength = WriteHostName(fsm, &RecordsBuffer[fsm->lRecordBufferHead]);
		
		fsm->lRecordBufferHead += ALIGN_PWR2(record->namelength, DNS_PARSED_ALIGNMENT);

		break;
	}
	case SOA:
	{
		if (pointer->dnsReferenceRecordOffset != MAX_UINT)
		{
			char* topLevelDomain = fsm->lQueryAnswerHead + pointer->dnsReferenceRecordOffset;
			DEBUGLOG("TOP LEVEL DOMAIN BEING SPECFIED: ");
			//PrintHostName(topLevelDomain, queryHead, 0);
		}

		fsm->lRecordBufferHead += sizeof(DNSRecordReference);

		int move = PrintHostName(fsm); //mname

		fsm->lAnswerProcessed += move;

		move = PrintHostName(fsm); //rname

		fsm->lAnswerProcessed += move;

		DNSSOA soa;

		CreateDNSSOARecordFromNetworkBytes(&soa, fsm);

		DEBUGLOG("Serial is : %u", soa.serial);
		DEBUGLOG("Refresh is : %u", soa.refresh);
		DEBUGLOG("Retry is : %u", soa.retry);
		DEBUGLOG("Expire is : %u", soa.expire);
		DEBUGLOG("Minimum is : %u", soa.minimum);

		break;
	}
	default:
		ERRORLOG("Unhandled response");
		break;
	}

	ref->size = fsm->lRecordBufferHead - startReference;

	return len;
}

int ProcessRawRecordsBuffer(DNSFSM* fsmPtr)
{
	for (uint32_t j = fsmPtr->lRecordBufferStart; j < fsmPtr->lRecordBufferHead;) 
	{
		uint32_t startReference = j;
		DNSRecordReference* ref = (DNSRecordReference*)&RecordsBuffer[j];

		switch (ref->type)
		{
		case A:
		{
			DNSARecord* childRecord = (DNSARecord*)(ref + 1);

			if (childRecord->referenceHostNameRecordID != MAX_UINT)
			{
				DNSRecordReference* nameRef = (DNSRecordReference*)&RecordsBuffer[childRecord->referenceHostNameRecordID];

				if (nameRef->type == CNAME)
				{
					DNSCNAMERecord* parentRecord = (DNSCNAMERecord*)&RecordsBuffer[childRecord->referenceHostNameRecordID + sizeof(DNSRecordReference)];
					parentRecord->arecordid[parentRecord->arecordcount++] = startReference;
				}
				else if (nameRef->type == NS) {
					DNSNSRecord* parentRecord = (DNSNSRecord*)&RecordsBuffer[childRecord->referenceHostNameRecordID + sizeof(DNSRecordReference)];
					parentRecord->arecordid[parentRecord->arecordcount++] = startReference;
				}
				else if (nameRef->type == MX)
				{
					DNSMXRecord* parentRecord = (DNSMXRecord*)&RecordsBuffer[childRecord->referenceHostNameRecordID + sizeof(DNSRecordReference)];
					parentRecord->arecordid[parentRecord->arecordcount++] = startReference;
				}
				else if (nameRef->type == QUERYHOSTNAME)
				{
					DNSQueryHostnameRecord* parentRecord = (DNSQueryHostnameRecord*)&RecordsBuffer[childRecord->referenceHostNameRecordID + sizeof(DNSRecordReference)];
					parentRecord->arecordid[parentRecord->arecordcount++] = startReference;
				}
			}
			break;
		}
		case AAAA:
		{
			DNSAAAARecord* childRecord = (DNSAAAARecord*)(ref + 1);

			if (childRecord->referenceHostNameRecordID != MAX_UINT)
			{
				DNSRecordReference* nameRef = (DNSRecordReference*)&RecordsBuffer[childRecord->referenceHostNameRecordID];

				if (nameRef->type == CNAME)
				{
					DNSCNAMERecord* parentRecord = (DNSCNAMERecord*)&RecordsBuffer[childRecord->referenceHostNameRecordID + sizeof(DNSRecordReference)];
					parentRecord->arecordid[parentRecord->arecordcount++] = startReference;
				}
				else if (nameRef->type == NS) {
					DNSNSRecord* parentRecord = (DNSNSRecord*)&RecordsBuffer[childRecord->referenceHostNameRecordID + sizeof(DNSRecordReference)];
					parentRecord->arecordid[parentRecord->arecordcount++] = startReference;
				}
				else if (nameRef->type == MX)
				{
					DNSMXRecord* parentRecord = (DNSMXRecord*)&RecordsBuffer[childRecord->referenceHostNameRecordID + sizeof(DNSRecordReference)];
					parentRecord->arecordid[parentRecord->arecordcount++] = startReference;
				}
				else if (nameRef->type == QUERYHOSTNAME)
				{
					DNSQueryHostnameRecord* parentRecord = (DNSQueryHostnameRecord*)&RecordsBuffer[childRecord->referenceHostNameRecordID + sizeof(DNSRecordReference)];
					parentRecord->arecordid[parentRecord->arecordcount++] = startReference;
				}
			}

			break;
		}
		case CNAME:
		{
			break;
		}
		case NS:
		{
			break;
		}
		case MX:
		{
			break;
		}
		}
		j += ref->size;
	}

	return 0;
}

void CreateDNSHeaderFromNetworkBytes(DNSHeader* header, DNSFSM* fsm)
{
	header->ID = MAKE_NETWORK_USHORT_FROM_BYTES(fsm->lQueryAnswerHead + fsm->lAnswerProcessed);
	header->flags = MAKE_NETWORK_USHORT_FROM_BYTES(fsm->lQueryAnswerHead + fsm->lAnswerProcessed + 2);
	header->QDCOUNT = MAKE_NETWORK_USHORT_FROM_BYTES(fsm->lQueryAnswerHead + fsm->lAnswerProcessed + 4);
	header->ANCOUNT = MAKE_NETWORK_USHORT_FROM_BYTES(fsm->lQueryAnswerHead + fsm->lAnswerProcessed + 6);
	header->NSCOUNT = MAKE_NETWORK_USHORT_FROM_BYTES(fsm->lQueryAnswerHead + fsm->lAnswerProcessed + 8);
	header->ARCOUNT = MAKE_NETWORK_USHORT_FROM_BYTES(fsm->lQueryAnswerHead + fsm->lAnswerProcessed + 10);

	fsm->lAnswerProcessed += sizeof(DNSHeader);
}

void CreateDNSAnswerFromNetworkBytes(DNSAnswer* answer, DNSFSM* fsm)
{
	answer->TYPE = MAKE_NETWORK_USHORT_FROM_BYTES(fsm->lQueryAnswerHead + fsm->lAnswerProcessed);
	answer->CLASS = MAKE_NETWORK_USHORT_FROM_BYTES(fsm->lQueryAnswerHead + fsm->lAnswerProcessed + 2);
	answer->TTL = MAKE_NETWORK_UINT_FROM_BYTES(fsm->lQueryAnswerHead + fsm->lAnswerProcessed + 4);
	answer->RDLENGTH = MAKE_NETWORK_USHORT_FROM_BYTES(fsm->lQueryAnswerHead + fsm->lAnswerProcessed + 8);

	fsm->lAnswerProcessed += DNS_ANSWER_WIRE_SIZE_BYTES;
}

void CreateDNSSOARecordFromNetworkBytes(DNSSOA* soa, DNSFSM* fsm)
{
	soa->serial = MAKE_NETWORK_UINT_FROM_BYTES(fsm->lQueryAnswerHead + fsm->lAnswerProcessed);
	soa->refresh = MAKE_NETWORK_UINT_FROM_BYTES(fsm->lQueryAnswerHead + fsm->lAnswerProcessed + 4);
	soa->retry = MAKE_NETWORK_UINT_FROM_BYTES(fsm->lQueryAnswerHead + fsm->lAnswerProcessed + 8);
	soa->expire = MAKE_NETWORK_UINT_FROM_BYTES(fsm->lQueryAnswerHead + fsm->lAnswerProcessed + 12);
	soa->minimum = MAKE_NETWORK_UINT_FROM_BYTES(fsm->lQueryAnswerHead + fsm->lAnswerProcessed + 16);

	fsm->lAnswerProcessed += sizeof(DNSSOA);
}

int PrintHostName(DNSFSM* fsm)
{
#if DNS_LOG_LVL >= 2
	int stringLength = 0;
	int recursionCount = 0;
	int moveInAnswer = 0;

	char* head = fsm->lQueryAnswerHead + fsm->lAnswerProcessed;
	char* iter = head;
	char count;

	while ((count = *iter++) && stringLength < 255)
	{
		if (count < 0)
		{
			uint16_t offsetp = (((uint16_t)count) << 8) | (iter[0] & 0xff);

			iter++;

			printf(".");

			if (offsetp & 0xC000)
			{
				if (!recursionCount)
				{
					moveInAnswer = (uintptr_t)iter - (uintptr_t)(head);
					recursionCount++;
				}

				offsetp &= 0x3FFF;

				iter = (fsm->lQueryAnswerHead + offsetp);
			}

			continue;
		}

		char* possibleTerminator = iter + count;

		int rem = dumpstring(iter, count, (int)possibleTerminator[0]);

		stringLength += rem;
		iter += rem;
	}

	if (!recursionCount)
	{
		moveInAnswer = (uintptr_t)iter - (uintptr_t)(head);
	}
	
	printf("\n");

	return moveInAnswer;
#else
	return 0;
#endif
}

int WriteHostName(DNSFSM* fsm, char* outWrite)
{
	int recursionCount = 0;
	int stringLength = 0;
	int moveInAnswer = 0;
	
	char* head = fsm->lQueryAnswerHead + fsm->lAnswerProcessed;
	char* iter = head;
	char count;

	while ((count = *iter++) && stringLength < 255)
	{
		if (count < 0)
		{
			uint16_t offsetp = (((uint16_t)count) << 8) | (iter[0] & 0xff);

			iter++;

			if (offsetp & 0xC000)
			{
				if (!recursionCount)
				{
					moveInAnswer = (uintptr_t)iter - (uintptr_t)(head);
					recursionCount++;
				}

				offsetp &= 0x3FFF;

				iter = (fsm->lQueryAnswerHead + offsetp);
			}

			continue;
		}

		char* possibleTerminator = iter + count;

		int writeStride = writestring(iter, count, (int)possibleTerminator[0], outWrite);

		stringLength += writeStride;
		outWrite += writeStride;
		iter += (writeStride - 1); //for next count in host name, sub 1 for terminator
	}

	if (!recursionCount)
	{
		moveInAnswer = (uintptr_t)iter - (uintptr_t)(head);
	}

	fsm->lAnswerProcessed += moveInAnswer;

	return stringLength;
}