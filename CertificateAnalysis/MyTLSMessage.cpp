#include "MyTLSMessage.h"
#include <sstream>


MyTLSMessage::MyTLSMessage(TcpReassemblyData rData, pcpp::ssl_tls_record_layer* tls, uint8_t* payload)
{
	m_conData = rData.m_conData;

	m_recordType = (uint8_t)tls->recordType;
	m_recordVersion = (uint16_t)_byteswap_ushort(tls->recordVersion);
	m_recordLength = (uint16_t)_byteswap_ushort(tls->length);

	m_payload = new uint8_t[m_recordLength];
	memcpy(m_payload, payload, m_recordLength);
}

MyTLSMessage::MyTLSMessage(TcpReassemblyData rData, pcpp::ssl_tls_record_layer* tls, uint8_t* payload, pcpp::ssl_tls_handshake_layer* handshake, int startIndex)
{
	m_conData = rData.m_conData;

	m_recordType = (uint8_t)tls->recordType;
	m_recordVersion = (uint16_t)_byteswap_ushort(tls->recordVersion);
	m_recordLength = handshake->length1 << 16 | _byteswap_ushort(handshake->length2);

	m_payload = new uint8_t[m_recordLength];
	memcpy(m_payload, payload + startIndex, m_recordLength);
}

uint8_t* MyTLSMessage::GetPayload()
{
	return m_payload;
}

std::string MyTLSMessage::GetServerIP()
{
	return m_conData.dstIP.toString();
}

bool MyTLSMessage::IsCertificateMessage()
{
	pcpp::ssl_tls_handshake_layer* handshake = (pcpp::ssl_tls_handshake_layer*)m_payload;
	if (handshake->handshakeType == pcpp::SSLHandshakeType::SSL_CERTIFICATE)
		return true;
	return false;
}

std::string thumbprint(X509* x509)
{
	static const char hexbytes[] = "0123456789ABCDEF";
	unsigned int md_size;
	unsigned char md[EVP_MAX_MD_SIZE];
	const EVP_MD* digest = EVP_get_digestbyname("sha1");
	X509_digest(x509, digest, md, &md_size);
	std::stringstream ashex;
	for (int pos = 0; pos < md_size; pos++)
	{
		ashex << hexbytes[(md[pos] & 0xf0) >> 4];
		ashex << hexbytes[(md[pos] & 0x0f) >> 0];
	}
	return ashex.str();
}

void MyTLSMessage::ExtractCertificateInfos(std::vector<X509*> *certChain)
{
	u_int certificates_length;

	pcpp::ssl_tls_handshake_layer* hand = (pcpp::ssl_tls_handshake_layer*)(m_payload);
	CertLen* certificates_len = (CertLen*)(m_payload + sizeof(pcpp::ssl_tls_handshake_layer));
	certificates_length = certificates_len->cert_lenght1 << 16 | _byteswap_ushort(certificates_len->cert_length2);
	m_payload = m_payload + sizeof(pcpp::ssl_tls_handshake_layer) + sizeof(CertLen);
	u_int idx = 0;

	//    std::cout << "Handshaketype: " << std::hex << hand->handshakeType <<  "- L1: << " << std::hex << hand->length1 << " - L2: " << std::hex << hand->length2 << std::endl;

	while (certificates_length != idx)
	{
		CertLen* cert_len = (CertLen*)(m_payload + idx);
		const uint8_t* startCertPoint = (uint8_t*)(m_payload + sizeof(CertLen) + idx);
		//        std::cout << "L1: << " << std::hex << cert_len->cert_lenght1 << " - L2: " << std::hex << cert_len->cert_length2 << std::endl;
		u_int len = cert_len->cert_lenght1 << 16 | _byteswap_ushort(cert_len->cert_length2);

		/*PCCERT_CONTEXT pcCert = CertCreateCertificateContext((X509_ASN_ENCODING | PKCS_7_ASN_ENCODING), startCertPoint, len);
		if (!pcCert)
		{
			std::cout << "Unable to parse certificate in PCCERT_CONTEXT\n" << std::endl;
		}*/

		
		X509* cert = d2i_X509(NULL, &startCertPoint, len);
		if (!cert) {
			std::cout << "Unable to parse certificate\n" << std::endl;
			return;
		}

		std::cout << thumbprint(cert) << std::endl;

//#define SHA1LEN 20
//		char buf[SHA1LEN];
//
//		const EVP_MD* digest = EVP_sha1();
//		unsigned digest_len;
//
//		int rc = X509_digest(cert, digest, (unsigned char*)buf, &digest_len);
//		if (rc == 0 || digest_len != SHA1LEN) {
//			;
//		}
//		else {
//			char strbuf[23 * SHA1LEN + 1];
//			hex_encode(buf, strbuf, SHA1LEN);
//			std::cout << strbuf << std::endl;
//		}

		// STACK_OF(X509_EXTENSION)* exts = cert->cert_info->extensions;


		certChain->push_back(cert);

		/*char *subj = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
		char *issuer = X509_NAME_oneline(X509_get_issuer_name(cert), NULL, 0);
		int raw = X509_check_ca(cert);

		std::cout << "Subject: " << subj << std::endl;
		std::cout << "Issuer: " << issuer << std::endl;
		if (raw)
			std::cout << "Root CA: true" << std::endl;
		else
			std::cout << "Root CA: false" << std::endl;*/
		idx = idx + len + sizeof(CertLen);
		startCertPoint = startCertPoint + len;
	}
}
