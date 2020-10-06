#pragma once

#include "TcpReassembly.h"
#include "PcapLiveDeviceList.h"
#include "PcapFileDevice.h"
#include "PlatformSpecificUtils.h"
#include "SystemUtils.h"
#include "PcapPlusPlusVersion.h"
#include <SSLCommon.h>

#include <SSLHandshake.h>
#include <SSLLayer.h>


#include <iostream>

class TcpReassemblyData
{

public:
	int m_direction;
	pcpp::ConnectionData m_conData;
	uint8_t* m_data;
	size_t m_data_len;

	TcpReassemblyData(int side, pcpp::ConnectionData con, const uint8_t* pay, size_t len);
	~TcpReassemblyData() {}
};


