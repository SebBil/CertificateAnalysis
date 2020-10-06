#pragma once

#include <vector>

#include "MyTLSMessage.h"

class MyTLSMessageBuilder
{
	std::vector<TcpReassemblyData> m_PartMessages;
	std::vector<TcpReassemblyData>::iterator m_PartMessagesIter;

	int m_idxStart;
	int m_idxEnd;
	size_t m_cur_len;
	size_t m_tls_len;


public:
	MyTLSMessageBuilder() { m_cur_len = 0; /* because of the first tls header */ m_idxStart = 0; }
	~MyTLSMessageBuilder() {}

	int AddPackage(TcpReassemblyData data, bool isFirst, int l, int idx);

	void CreateTLSMessage(std::vector<MyTLSMessage>* list);

	size_t GetCurrentSize() { return m_PartMessages.size(); }
	void Clear();
};


