#include "TcpReassemblyData.h"

TcpReassemblyData::TcpReassemblyData(int side, pcpp::ConnectionData con, const uint8_t* pay, size_t len)
{
	m_direction = side;
	m_conData = con;
	m_data_len = len;
	m_data = new uint8_t[len];
	memcpy(m_data, pay, len);
}
