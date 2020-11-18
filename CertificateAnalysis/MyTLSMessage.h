#pragma once

#include "TcpReassemblyData.h"

#include <iomanip>

#include <openssl/x509v3.h>
#include <openssl/bn.h>
#include <openssl/asn1.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/pem.h>
#include <openssl/bio.h>


#pragma pack(push, 1)
struct CertLen {
	uint8_t cert_lenght1;
	uint16_t cert_length2;
};
#pragma pack(pop)


class MyTLSMessage
{
	pcpp::ConnectionData m_conData;

	uint8_t m_recordType;
	uint16_t m_recordVersion;
	uint16_t m_recordLength;

	uint8_t* m_payload;

public:
	MyTLSMessage(TcpReassemblyData rData, pcpp::ssl_tls_record_layer* tls, uint8_t* payload);
	MyTLSMessage(TcpReassemblyData rData, pcpp::ssl_tls_record_layer* tls, uint8_t* payload, pcpp::ssl_tls_handshake_layer* handshake, int startIndex);


	uint8_t* GetPayload();
	std::string GetServerIP();
	bool IsCertificateMessage();
	void ExtractCertificateInfos(std::vector<X509*>*);
};



