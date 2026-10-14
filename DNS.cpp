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
	int lDnsQueryCount;
	uint32_t lAnswerPoolCount;
	uint32_t lDnsQueryLength;
	uint32_t lAnswerPoolAmount;
	uint32_t lRecordBufferAmount;
	uint32_t lRecordBufferStart;
	uint32_t lRecordBufferHead;
} DNSFSM;

#define KB 1024
#define MB 1024 * KB
#define GB 1024 * MB

#define DNSANSPOOLSIZE 512*KB
#define DNSQUERYPOOLSIZE 256*KB
#define FUNCANSWEPOOL 2 * MB
#define RECORDPOOLSIZE 256*KB

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

#define MAX_RECURSE_LIMIT 10

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

static int PrintHostName(char* str, char *queryHead, int recursionCount)
{
#if DNS_LOG_LVL >= 2
	if (recursionCount >= 255) return -1;
	int i = 0;
	char* iter = str;
	char count;
	while (++i && (count = *iter++))
	{
		if (count < 0)
		{
			uint16_t offsetp = (((uint16_t)count) << 8) | (iter[0] & 0xff);

			i++;
			iter++;
			printf(".");
			
			if (offsetp & 0xC000)
			{
				offsetp &= 0x3FFF;
				iter = (queryHead + offsetp);
				int rem = PrintHostName(iter, queryHead, recursionCount+1);

				if (rem < 0) return rem;
			}

			break;
		} 

		char* stub = iter + count;

		int rem = dumpstring(iter, count, (int)stub[0]);
			
		i += rem;
		iter += rem;
	}
	if (!recursionCount) {
		printf("\n");
	}
	return i;
#else
	return 0;
#endif
}

static int WriteHostName(char* str, char* queryHead, int recursionCount, char *write)
{
	if (recursionCount >= 255) return -1;
	int i = 0;
	char* iter = str;
	char count;
	while (count = *iter++)
	{
		if (count < 0)
		{
			uint16_t offsetp = (((uint16_t)count) << 8) | (iter[0] & 0xff);

			iter++;

			if (offsetp & 0xC000)
			{
				offsetp &= 0x3FFF;

				iter = (queryHead + offsetp);

				int rem = WriteHostName(iter, queryHead, recursionCount+1, write);

				if (rem < 0) return rem;

				i += rem;
			}

			break;
		}

		char* stub = iter + count;

		int rem = writestring(iter, count, (int)stub[0], write);

		i += rem;
		iter += (rem-1); //for next count in host name
		write += rem;
	}

	return i+1;
}

static int HandleDNSAnswer(DNSAnswer* answer, char* queryHead, DNSPointer* pointer, uint32_t* lRecordBufferPtr);
static int HandleDNSNSNames(DNSAnswer* answer, char* queryHead, DNSPointer* pointer, uint32_t* lRecordBufferPtr);
static int HandlePointerCondition(uint16_t* iter, DNSPointer* pointer, uint32_t recordsBufferReader, int recordsBufferCounter);
static int HandleDNSAdditional(DNSAnswer* answer, char* queryHead, DNSPointer* pointer, uint32_t* lRecordBufferPtr);
static int ProcessBuffer(DNSFSM* fsmPtr, DNSQueryResult* resultSpace);
static void PrintIPv4(uint32_t addr);
static void PrintIPv6(char* addr);
static void PrintRecordHostname(char* ptr);
static int DeDeuplicateIPv4(char* recordBuffer, uint16_t count, uint32_t* recordoffsets, int addr);
static int DeDeuplicateIPv6(char* recordBuffer, uint16_t count, uint32_t* recordoffsets, char* addr);
static int WriteRawToParsed(DNSFSM* fsmPtr);

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

	dnsResolver->sin_addr.s_addr = ntohl(addr);

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
	header->ID = htons((rand() % (USHRT_MAX + 1)));

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

	uint32_t lQueryCount = dnsFSM->lDnsQueryCount;

	uint32_t lAnswerPoolCount = dnsFSM->lAnswerPoolCount;

	uint32_t lRecordBufferCtr = dnsFSM->lRecordBufferStart;

	DEBUGLOG("Searching in IPv4 address %s", IPv4Decode);

	DNSHeader* header = (DNSHeader*)(QueryPool + lQueryCount);

	SOCKET ConnectionSocket = INVALID_SOCKET;

	ConnectionSocket = socket(dnsServer->sin_family, SOCK_DGRAM, IPPROTO_UDP);

	if (ConnectionSocket == INVALID_SOCKET) 
	{
		DEBUGLOG("Error at socket(): %ld", WSAGetLastError());
		return -1;
	}

	int res = connect(ConnectionSocket, ((sockaddr*)dnsServer), sizeof(sockaddr_in));

	if (res == SOCKET_ERROR) 
	{
		closesocket(ConnectionSocket);
		return -1;
	}

	res = send(ConnectionSocket, (char*)header, dnsFSM->lDnsQueryLength, 0);

	if (res == SOCKET_ERROR)
	{
		DEBUGLOG("send failed with error: %d", WSAGetLastError());
		closesocket(ConnectionSocket);
		return -1;
	}

	DEBUGLOG("Bytes sent %ld", res);

	res = recv(ConnectionSocket, RawDNSAnswerPool + lAnswerPoolCount, dnsFSM->lAnswerPoolAmount - lAnswerPoolCount, 0);
	if (res > 0) 
	{
		DEBUGLOG("Bytes received: %d", res);
	}
	else if (res == 0)
		DEBUGLOG("Connection closed");
	else
		DEBUGLOG("recv failed with error: %d", WSAGetLastError());

	closesocket(ConnectionSocket);

	char* lQueryAnswerHead = (char*)(RawDNSAnswerPool + lAnswerPoolCount);

	lAnswerPoolCount += res;

	lQueryCount += dnsFSM->lDnsQueryLength;

	int found = 0;

	DNSHeader* headera = (DNSHeader*)(lQueryAnswerHead);

	DEBUGLOG("Header ID: %hx", ntohs(headera->ID));
	DEBUGLOG("flags ID: %hx", ntohs(headera->flags));
	PrintDNSFlags(ntohs(headera->flags));
	DEBUGLOG("QDCOUNT ID: %hx", ntohs(headera->QDCOUNT));
	DEBUGLOG("ANCOUNT ID: %hx", ntohs(headera->ANCOUNT));
	DEBUGLOG("NSCOUNT ID: %hx", ntohs(headera->NSCOUNT));
	DEBUGLOG("ARCOUNT ID: %hx", ntohs(headera->ARCOUNT));

	int ret = PrintHostName((char*)(lQueryAnswerHead + sizeof(DNSHeader)), lQueryAnswerHead, 0);

	uint16_t rcode = ntohs(headera->flags) & 0xf;

	uint16_t anCount = ntohs(headera->ANCOUNT);

	uint16_t nDomainCount = ntohs(headera->NSCOUNT);

	uint16_t adRecordCount = ntohs(headera->ARCOUNT);

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

	uint16_t answerOffset = sizeof(DNSHeader);

	DNSRecordReference* ref = (DNSRecordReference*)&RecordsBuffer[lRecordBufferCtr];
	ref->packet = (void*)lQueryAnswerHead;
	ref->offset = answerOffset;
	ref->type = QUERYHOSTNAME;
	ref->size = sizeof(DNSRecordReference) + sizeof(DNSQueryHostnameRecord);

	lRecordBufferCtr += sizeof(DNSRecordReference);

	DNSQueryHostnameRecord* queryHostnameRecord = (DNSQueryHostnameRecord*)&RecordsBuffer[lRecordBufferCtr];

	queryHostnameRecord->arecordcount = 0;

	lRecordBufferCtr += sizeof(DNSQueryHostnameRecord);

	int writeName = WriteHostName((lQueryAnswerHead + answerOffset), lQueryAnswerHead, 0, &RecordsBuffer[lRecordBufferCtr]);

	answerOffset += (writeName + sizeof(DNSQuestion));

	writeName = ALIGN_PWR2(writeName, DNS_PARSED_ALIGNMENT);

	ref->size += writeName;

	lRecordBufferCtr += writeName;

	for (uint16_t i = 0; i < anCount; i++)
	{
		char* ptr = lQueryAnswerHead + answerOffset;

		DNSPointer dnsPointer =
		{
			MAX_UINT, MAX_UINT, MAX_UINT
		};

		int move = HandlePointerCondition((uint16_t*)ptr, &dnsPointer, dnsFSM->lRecordBufferStart, lRecordBufferCtr);

		ptr += move;
		answerOffset += move;

		DNSAnswer* answer = (DNSAnswer*)ptr;

		answerOffset += sizeof(DNSAnswer);

		dnsPointer.recordOffset = answerOffset;

		answerOffset += HandleDNSAnswer(answer, lQueryAnswerHead, &dnsPointer, &lRecordBufferCtr);
	}

	for (uint16_t i = 0; i < nDomainCount; i++)
	{
		char* ptr = lQueryAnswerHead + answerOffset;

		DNSPointer dnsPointer =
		{
			MAX_UINT, MAX_UINT, MAX_UINT
		};

		int move = HandlePointerCondition((uint16_t*)ptr, &dnsPointer, dnsFSM->lRecordBufferStart, lRecordBufferCtr);

		ptr += move;
		answerOffset += move;

		DNSAnswer* answer = (DNSAnswer*)ptr;

		answerOffset += sizeof(DNSAnswer);

		dnsPointer.recordOffset = answerOffset;

		answerOffset += HandleDNSNSNames(answer, lQueryAnswerHead, &dnsPointer, &lRecordBufferCtr);
	}

	for (uint16_t i = 0; i < adRecordCount; i++)
	{
		char* ptr = lQueryAnswerHead + answerOffset;

		DNSPointer dnsPointer =
		{
			MAX_UINT, MAX_UINT, MAX_UINT
		};

		int move = HandlePointerCondition((uint16_t*)ptr, &dnsPointer, dnsFSM->lRecordBufferStart, lRecordBufferCtr);

		ptr += move;
		answerOffset += move;

		DNSAnswer* answer = (DNSAnswer*)ptr;

		answerOffset += sizeof(DNSAnswer);

		dnsPointer.recordOffset = answerOffset;

		answerOffset += HandleDNSAdditional(answer, lQueryAnswerHead, &dnsPointer, &lRecordBufferCtr);
	}

	dnsFSM->lRecordBufferHead = lRecordBufferCtr;
	dnsFSM->lDnsQueryCount = lQueryCount;
	dnsFSM->lAnswerPoolCount = lAnswerPoolCount;

	WriteRawToParsed(dnsFSM);

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
	fsm.lAnswerPoolCount = RawDNSAnswerCount;
	fsm.lRecordBufferStart = RecordsBufferCounter;
	fsm.lRecordBufferStart = 0;
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
		int ResultCount = ProcessBuffer(&fsm, returnHeader);

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

int ProcessBuffer(DNSFSM* fsmPtr, DNSQueryResult* resultSpace)
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

int HandlePointerCondition(uint16_t* iter, DNSPointer* pointer, uint32_t recordsBufferReader, int recordsBufferCounter)
{
	uint16_t lPointer = ntohs(*iter);;
	
	int ret = 0;

	if (lPointer & 0xC000)
	{
		lPointer &= 0x3fff;
		int i = 0;
		for (uint32_t j = recordsBufferReader; j < recordsBufferCounter;) 
		{
			DNSRecordReference* ref = (DNSRecordReference*)&RecordsBuffer[j];
			if (ref->offset == lPointer)
			{
				DEBUGLOG("This is a reference to the %d response", i+1);
				pointer->internalRecordBufferOffset = j;
				break;
			}
			j += ref->size;
			i++;
		}

		pointer->dnsReferenceRecordOffset = lPointer;

		ret = 2;
	}

	return ret;
}

int HandleDNSNSNames(DNSAnswer* answer, char* queryHead, DNSPointer* pointer, uint32_t* lRecordBufferPtr)
{
	DEBUGLOG("Type %hx", ntohs(answer->TYPE));
	DEBUGLOG("Class %hx", ntohs(answer->CLASS));
	DEBUGLOG("TTL %lx", ntohl(answer->TTL));
	DEBUGLOG("RDLENGTH %hx", ntohs(answer->RDLENGTH));

	uint32_t startReference = *lRecordBufferPtr;

	uint32_t llRecordBufferPtr = *lRecordBufferPtr;

	DNSRecordReference* ref = (DNSRecordReference*)&RecordsBuffer[llRecordBufferPtr];
	ref->packet = (void*)queryHead;
	ref->offset = pointer->recordOffset;
	ref->type = ntohs(answer->TYPE);

	int len = ntohs(answer->RDLENGTH);

	char* RDDATA = (char*)(answer + 1);

	llRecordBufferPtr += sizeof(DNSRecordReference);

	switch (ref->type)
	{
		case SOA:
		{
			if (pointer->dnsReferenceRecordOffset != MAX_UINT)
			{
				char* topLevelDomain = queryHead + pointer->dnsReferenceRecordOffset;
				DEBUGLOG("TOP LEVEL DOMAIN BEING SPECFIED: ");
				PrintHostName(topLevelDomain, queryHead, 0);
			}

			int move = PrintHostName(RDDATA, queryHead, 0);

			RDDATA += move;

			move = PrintHostName(RDDATA, queryHead, 0);

			RDDATA += move;

			DEBUGLOG("Serial is : %hu  ", ntohl(*((uint32_t*)RDDATA)));
			RDDATA += 4;
			DEBUGLOG("Refresh is : %hu  ", ntohl(*((uint32_t*)RDDATA)));
			RDDATA += 4;
			DEBUGLOG("Retry is : %hu  ", ntohl(*((uint32_t*)RDDATA)));
			RDDATA += 4;
			DEBUGLOG("Expire is : %hu  ", ntohl(*((uint32_t*)RDDATA)));
			RDDATA += 4;
			DEBUGLOG("Minimum is : %hu  ", ntohl(*((uint32_t*)RDDATA)));
			RDDATA += 4;
			break;
		}
		case NS:
		{
			PrintHostName(RDDATA, queryHead, 0);
			
			DNSNSRecord* record = (DNSNSRecord*)&RecordsBuffer[llRecordBufferPtr];
			
			llRecordBufferPtr += sizeof(DNSNSRecord);
			
			record->namelength = WriteHostName(RDDATA, queryHead, 0, &RecordsBuffer[llRecordBufferPtr]);
			record->arecordcount = 0;
			record->queryAlias = pointer->internalRecordBufferOffset;
			record->cnameAlias = pointer->dnsReferenceRecordOffset;

			llRecordBufferPtr += ALIGN_PWR2(record->namelength, DNS_PARSED_ALIGNMENT);
			break;
		}
	}

	ref->size = llRecordBufferPtr - startReference;

	*lRecordBufferPtr = llRecordBufferPtr;

	return len;
}

int HandleDNSAnswer(DNSAnswer* answer, char* queryHead, DNSPointer* pointer, uint32_t* lRecordBufferPtr)
{
	DEBUGLOG("Type %hx", ntohs(answer->TYPE));
	DEBUGLOG("Class %hx", ntohs(answer->CLASS));
	DEBUGLOG("TTL %lx", ntohl(answer->TTL));
	DEBUGLOG("RDLENGTH %hx", ntohs(answer->RDLENGTH));

	uint32_t startReference = *lRecordBufferPtr;

	uint32_t llRecordBufferPtr = startReference;

	DNSRecordReference* ref = (DNSRecordReference*)&RecordsBuffer[llRecordBufferPtr];
	ref->packet = (void*)queryHead;
	ref->offset = pointer->recordOffset;
	ref->type = ntohs(answer->TYPE);

	int len = ntohs(answer->RDLENGTH);

	char* RDDATA = (char*)(answer + 1);

	switch (ref->type)
	{
	case A:
	{
		if (len != RDLEN_A)
		{
			ERRORLOG("DNS Answer: A record is not matching RDLEN: size %d, expected %d\n", len, RDLEN_A);
			break;
		}

		llRecordBufferPtr += sizeof(DNSRecordReference);

		DNSARecord* record = (DNSARecord*)&RecordsBuffer[llRecordBufferPtr];

		llRecordBufferPtr += sizeof(DNSARecord);

		uint32_t addr = 0;
		for (int i = 0; i < len - 1; i++)
		{
			addr |= (RDDATA[i] & 0xff);
			addr <<= 8;
		}
		addr |= (RDDATA[3] & 0xff);

		record->addr = addr;
		record->referenceHostNameRecordID = pointer->internalRecordBufferOffset;
		record->dnsAnswerHostRecordID = pointer->dnsReferenceRecordOffset;
		PrintIPv4(addr);
		
		break;
	}
	case CNAME:
	{
		llRecordBufferPtr += sizeof(DNSRecordReference);
		PrintHostName(RDDATA, queryHead, 0);
		DNSCNAMERecord* record = (DNSCNAMERecord*)&RecordsBuffer[llRecordBufferPtr];
		llRecordBufferPtr += sizeof(DNSCNAMERecord);
		
		record->namelength = WriteHostName(RDDATA, queryHead, 0, &RecordsBuffer[llRecordBufferPtr]);
		record->arecordcount = 0;	
		record->queryAlias = pointer->internalRecordBufferOffset;
		record->cnameAlias = pointer->dnsReferenceRecordOffset;

		llRecordBufferPtr += ALIGN_PWR2(record->namelength, DNS_PARSED_ALIGNMENT);
		break;
	}
	case NS:
	{
		llRecordBufferPtr += sizeof(DNSRecordReference);
		PrintHostName(RDDATA, queryHead, 0);
		DNSNSRecord* record = (DNSNSRecord*)&RecordsBuffer[llRecordBufferPtr];
		llRecordBufferPtr += sizeof(DNSNSRecord);
		
		record->namelength = WriteHostName(RDDATA, queryHead, 0, &RecordsBuffer[llRecordBufferPtr]);
		record->arecordcount = 0;
		record->queryAlias = pointer->internalRecordBufferOffset;
		record->cnameAlias = pointer->dnsReferenceRecordOffset;

		llRecordBufferPtr += ALIGN_PWR2(record->namelength, DNS_PARSED_ALIGNMENT);
		break;
	}
	case MX:
	{
		llRecordBufferPtr += sizeof(DNSRecordReference);
		uint16_t* pref = (uint16_t*)RDDATA;
		RDDATA += 2;
		ref->offset += 2;
		PrintHostName(RDDATA, queryHead, 0);
		DNSMXRecord* record = (DNSMXRecord*)&RecordsBuffer[llRecordBufferPtr];
		llRecordBufferPtr += sizeof(DNSMXRecord);

		record->preference = ntohs(*pref);
		record->namelength = WriteHostName(RDDATA, queryHead, 0, &RecordsBuffer[llRecordBufferPtr]);
		record->arecordcount = 0;
		record->queryAlias = pointer->internalRecordBufferOffset;
		record->cnameAlias = pointer->dnsReferenceRecordOffset;

		llRecordBufferPtr += ALIGN_PWR2(record->namelength, DNS_PARSED_ALIGNMENT);
		break;
	}
	default:
		ERRORLOG("Unhandled response");
		break;
	}

	ref->size = llRecordBufferPtr - startReference;

	*lRecordBufferPtr = llRecordBufferPtr;

	return len;
}

int HandleDNSAdditional(DNSAnswer* answer, char* queryHead, DNSPointer* pointer, uint32_t* lRecordBufferPtr)
{
	DEBUGLOG("Type %hx", ntohs(answer->TYPE));
	DEBUGLOG("Class %hx", ntohs(answer->CLASS));
	DEBUGLOG("TTL %lx", ntohl(answer->TTL));
	DEBUGLOG("RDLENGTH %hx", ntohs(answer->RDLENGTH));

	uint32_t startReference = *lRecordBufferPtr;

	uint32_t llRecordBufferPtr = *lRecordBufferPtr;

	DNSRecordReference* ref = (DNSRecordReference*)&RecordsBuffer[llRecordBufferPtr];
	ref->packet = (void*)queryHead;
	ref->offset = pointer->recordOffset;
	ref->type = ntohs(answer->TYPE);

	int len = ntohs(answer->RDLENGTH);

	char* RDDATA = (char*)(answer + 1);

	switch (ref->type)
	{
	case A:
	{
		if (len != RDLEN_A)
		{
			ERRORLOG("DNS Additional: A record is not matching RDLEN: size %d, expected %d\n", len, RDLEN_A);
			break;
		}

		llRecordBufferPtr += sizeof(DNSRecordReference);

		DNSARecord* record = (DNSARecord*)&RecordsBuffer[llRecordBufferPtr];

		llRecordBufferPtr += sizeof(DNSARecord);

		uint32_t addr = 0;

		for (int i = 0; i < len - 1; i++)
		{
			addr |= (RDDATA[i] & 0xff);
			addr <<= 8;
		}
		addr |= (RDDATA[len-1] & 0xff);

		PrintIPv4(addr);

		record->addr = addr;
		record->referenceHostNameRecordID = pointer->internalRecordBufferOffset;
		record->dnsAnswerHostRecordID = pointer->dnsReferenceRecordOffset;
		break;
	}
	case AAAA:
	{
		if (len != RDLEN_AAAA)
		{
			ERRORLOG("DNS Additional: AAAA record is not matching RDLEN: size %d, expected %d\n", len, RDLEN_AAAA);
			break;
		}

		llRecordBufferPtr += sizeof(DNSRecordReference);

		DNSAAAARecord* record = (DNSAAAARecord*)&RecordsBuffer[llRecordBufferPtr];

		llRecordBufferPtr += sizeof(DNSAAAARecord);

		record->referenceHostNameRecordID = pointer->internalRecordBufferOffset;
		record->dnsAnswerHostRecordID = pointer->dnsReferenceRecordOffset;
		
		for (int i = 0; i < len; i++)
		{
			record->addr[15 - i] = (RDDATA[i] & 0xff);
		}

		PrintIPv6(record->addr);

		break;
	}
	default:
		ERRORLOG("Unhandled response");
		break;
	}

	ref->size = llRecordBufferPtr - startReference;

	*lRecordBufferPtr = llRecordBufferPtr;

	return len;
}

static int WriteRawToParsed(DNSFSM* fsmPtr)
{
	int ResultCount = 0;
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
	return ResultCount;
}