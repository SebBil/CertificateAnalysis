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
	return "Server IP: " + m_conData.dstIP.toString();
}

bool MyTLSMessage::IsCertificateMessage()
{
	pcpp::ssl_tls_handshake_layer* handshake = (pcpp::ssl_tls_handshake_layer*)m_payload;
	if (handshake->handshakeType == pcpp::SSLHandshakeType::SSL_CERTIFICATE)
		return true;
	return false;
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

std::vector<std::string> subject_alt_names(X509* x509)
{
	std::vector<std::string> list;
	GENERAL_NAMES* subjectAltNames = (GENERAL_NAMES*)X509_get_ext_d2i(x509, NID_subject_alt_name, NULL, NULL);
	for (int i = 0; i < sk_GENERAL_NAME_num(subjectAltNames); i++)
	{
		GENERAL_NAME* gen = sk_GENERAL_NAME_value(subjectAltNames, i);
		if (gen->type == GEN_URI || gen->type == GEN_DNS || gen->type == GEN_EMAIL)
		{
			ASN1_IA5STRING* asn1_str = gen->d.uniformResourceIdentifier;
			std::string san = std::string((char*)ASN1_STRING_data(asn1_str), ASN1_STRING_length(asn1_str));
			list.push_back(san);
		}
		else if (gen->type == GEN_IPADD)
		{
			unsigned char* p = gen->d.ip->data;
			if (gen->d.ip->length == 4)
			{
				std::stringstream ip;
				ip << (int)p[0] << '.' << (int)p[1] << '.' << (int)p[2] << '.' << (int)p[3];
				list.push_back(ip.str());
			}
			else //if(gen->d.ip->length == 16) //ipv6?
			{
				//std::cerr << "Not implemented: parse sans ("<< __FILE__ << ":" << __LINE__ << ")" << endl;
			}
		}
		else
		{
			//std::cerr << "Not implemented: parse sans ("<< __FILE__ << ":" << __LINE__ << ")" << endl;
		}
	}
	GENERAL_NAMES_free(subjectAltNames);
	return list;
}