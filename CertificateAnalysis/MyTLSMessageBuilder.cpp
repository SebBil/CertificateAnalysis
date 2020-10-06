#include "MyTLSMessageBuilder.h"

void MyTLSMessageBuilder::Clear()
{
	m_cur_len = 0;
	m_idxStart = 0;
	m_PartMessages.clear();
	m_tls_len = 0;
}

int MyTLSMessageBuilder::AddPackage(TcpReassemblyData data, bool isFirst, int l, int idx)
{
	if (isFirst)
	{
		m_tls_len = l;
		m_idxStart = idx;

		idx += 5;
		m_cur_len -= idx;
	}
	m_cur_len += data.m_data_len;

	m_PartMessages.push_back(data);

	m_idxEnd = m_cur_len - m_tls_len;
	return m_cur_len - m_tls_len;
}

void MyTLSMessageBuilder::CreateTLSMessage(std::vector<MyTLSMessage>* list)
{
	// check the SSL handshake record type
	pcpp::ssl_tls_record_layer* tls;
	tls = (pcpp::ssl_tls_record_layer*)(m_PartMessages[0].m_data + m_idxStart);


	uint8_t* payload;
	uint8_t* tls_payload;

	payload = (uint8_t*)malloc(m_tls_len + 5);
	size_t partSize = m_PartMessages.size();
	size_t index = 0;
	for (int i = 0; i < partSize; i++)
	{
		if (i == 0)
		{
			// first packet have set start index
			memcpy(payload + index, m_PartMessages[i].m_data + m_idxStart, m_PartMessages[i].m_data_len - m_idxStart);
			index += m_PartMessages[i].m_data_len - m_idxStart;
			continue;
		}

		if (i == partSize - 1)
		{
			// last packet have set the end index
			memcpy(payload + index, m_PartMessages[i].m_data, m_PartMessages[i].m_data_len - m_idxEnd);
			index += m_PartMessages[i].m_data_len - m_idxEnd;
			continue;
		}

		memcpy(payload + index, m_PartMessages[i].m_data, m_PartMessages[i].m_data_len);
		index += m_PartMessages[i].m_data_len;
	}

	if (!pcpp::SSLLayer::IsSSLMessage(m_PartMessages[0].m_conData.srcPort, m_PartMessages[0].m_conData.dstPort, (uint8_t*)payload, index))
		return;

	tls = (pcpp::ssl_tls_record_layer*)payload;
	if (tls->recordType != pcpp::SSL_HANDSHAKE)
		return;

	tls_payload = (uint8_t*)(payload + sizeof(pcpp::ssl_tls_record_layer));
	u_int tls_len = _byteswap_ushort(tls->length);
	pcpp::ssl_tls_handshake_layer* handshake = (pcpp::ssl_tls_handshake_layer*)(payload + 5);
	u_int hand_len = handshake->length1 << 16 | _byteswap_ushort(handshake->length2);

	if (hand_len + 4 != tls_len)
	{
		// Multiple handshake messages!!!
		u_int len;
		u_int index = 0;
		int idx_start = 5;
		int idx_end = 5;

		while (tls_len != 0)
		{
			len = handshake->length1 << 16 | _byteswap_ushort(handshake->length2);

			idx_end += len + 4;
			index += len + 4;

			// safe the TLS Message
			// list->push_back(MyTLSMessage(tls, test_payload, idx_start - 1, len + 4,
			list->push_back(MyTLSMessage(m_PartMessages[0], tls, payload, handshake, idx_start));

			tls_len -= len + 4;
			handshake = (pcpp::ssl_tls_handshake_layer*)(payload + 5 + index);
			idx_start = idx_end;
		}
	}
	else
	{
		list->push_back(MyTLSMessage(m_PartMessages[0], tls, tls_payload));
	}
}
