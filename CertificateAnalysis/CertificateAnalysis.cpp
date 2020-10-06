
#include <map>
#include <tuple>
#include <stdlib.h>
#include <sstream>
#include <thread> 
#include <cmath>
#include <boost/program_options.hpp>
#include <boost/algorithm/string.hpp>

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bio.h>
#include <openssl/pem.h>

#include "MyTLSMessageBuilder.h"
#include "TcpReassemblyData.h"

#undef min
#undef max

#include <matplot/matplot.h>

#define MY_ENCODING_TYPE  (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING)

static int messagesEndcon = 0;
static int messagesStartCon = 0;
static int messagesReady = 0;
static bool verbose = false;

int countCertificateMessagePerConnection = 0;
int countMatchCertSubj = 0;
int countCertNotExist = 0;
int countMatchCert = 0;
int countMatchSubj = 0;

// typedef representing the connection manager and its iterator
typedef std::map<uint32_t, std::vector<TcpReassemblyData>> TcpReassemblyConnMgr;
typedef std::map<uint32_t, std::vector<TcpReassemblyData>>::iterator TcpReassemblyConnMgrIter;

typedef std::vector<MyTLSMessage> TLSMessageList;


std::vector<std::pair<int, X509*>> m_trustedCertificateListCount;
std::vector<int> m_trustedCertificateListCountValues;

std::vector<std::vector<X509*>> AllCertsChain;

namespace po = boost::program_options;
using namespace matplot;


/**
 * The callback being called by the TCP reassembly module whenever new data arrives on a certain connection
 */
static void tcpReassemblyMsgReadyCallback(int8_t sideIndex, const pcpp::TcpStreamData& tcpData, void* userCookie)
{
	messagesReady++;
	// extract the connection manager from the user cookie
	TcpReassemblyConnMgr* connMgr = (TcpReassemblyConnMgr*)userCookie;

	// check if this flow already appears in the connection manager. If not add it
	TcpReassemblyConnMgrIter iter = connMgr->find(tcpData.getConnectionData().flowKey);

	if (iter == connMgr->end())
	{
		std::vector<TcpReassemblyData> tmp;
		connMgr->insert(std::make_pair(tcpData.getConnectionData().flowKey, tmp));
		iter = connMgr->find(tcpData.getConnectionData().flowKey);
	}


	iter->second.push_back(TcpReassemblyData(sideIndex, tcpData.getConnectionData(), tcpData.getData(), tcpData.getDataLength()));

}
/**
 * The callback being called by the TCP reassembly module whenever a new connection is found. This method adds the connection to the connection manager
 */
static void tcpReassemblyConnectionStartCallback(const pcpp::ConnectionData& connectionData, void* userCookie)
{
	messagesStartCon++;
	// get a pointer to the connection manager
	TcpReassemblyConnMgr* connMgr = (TcpReassemblyConnMgr*)userCookie;

	// look for the connection in the connection manager
	TcpReassemblyConnMgrIter iter = connMgr->find(connectionData.flowKey);

	// assuming it's a new connection
	if (iter == connMgr->end())
	{
		// add it to the connection manager
		std::vector<TcpReassemblyData> tmp;
		connMgr->insert(std::make_pair(connectionData.flowKey, tmp));
	}
}

/**
 * The callback being called by the TCP reassembly module whenever a connection is ending. This method removes the connection from the connection manager and writes the metadata file if requested
 * by the user
 */
static void tcpReassemblyConnectionEndCallback(const pcpp::ConnectionData& connectionData, pcpp::TcpReassembly::ConnectionEndReason reason, void* userCookie)
{
	messagesEndcon++;
	TLSMessageList TlsMessages;

	// get a pointer to the connection manager
	TcpReassemblyConnMgr* connMgr = (TcpReassemblyConnMgr*)userCookie;

	// find the connection in the connection manager by the flow key
	TcpReassemblyConnMgrIter iter = connMgr->find(connectionData.flowKey);

	// connection wasn't found - shouldn't get here
	if (iter == connMgr->end())
		return;

	// when connection end analyse each packet for TLS messages and create new instances, at the end erase the connection from the manager
	pcpp::ssl_tls_record_layer* tls = nullptr;
	uint8_t* tls_payload = nullptr;
	int prev_len;

	bool reassemble = false;

	// build all TLS Messages of this Connection
	MyTLSMessageBuilder builder;
	
	// reassemble Algorithm
	for (auto y : iter->second)
	{
		size_t pkt_length = y.m_data_len;

		if (reassemble)
		{
			// Add package to Builder
			int ret = builder.AddPackage(y, false, 0, 0);
			if (ret < 0)
			{
				// the next frame is also a part of a message that goes over more packets
				continue;
			}
			else if (ret == 0)
			{
				// -> Multiple Handshake Messages
				builder.CreateTLSMessage(&TlsMessages);
				builder.Clear();
				reassemble = false;
				continue;
			}
			else
			{
				builder.CreateTLSMessage(&TlsMessages);
				builder.Clear();
				reassemble = false;

				u_int curManageIndex = pkt_length - ret;
				tls = (pcpp::ssl_tls_record_layer*)(y.m_data + curManageIndex);
				tls_payload = (uint8_t*)(y.m_data + curManageIndex + sizeof(pcpp::ssl_tls_record_layer));
				pkt_length = ret;


				// handle the rest of the packet
				while (pkt_length != 0)
				{
					u_int l = _byteswap_ushort(tls->length);
					if (l > pkt_length)
					{
						builder.AddPackage(y, true, l, curManageIndex);
						reassemble = true;
						break;
					}
					if (tls->recordType == pcpp::SSL_HANDSHAKE)
					{
						TlsMessages.push_back(MyTLSMessage(y, tls, tls_payload));
					}
					pkt_length -= sizeof(pcpp::ssl_tls_record_layer) + l;
					tls = (pcpp::ssl_tls_record_layer*)(tls_payload + l);
					tls_payload = (uint8_t*)(tls_payload + sizeof(pcpp::ssl_tls_record_layer) + l);
					curManageIndex += l + sizeof(pcpp::ssl_tls_record_layer);
					if (pkt_length > 1600)
					{
						std::cout << "[!] Something went wrong in handle rest of the packet" << std::endl;
						break;
					}
				}
				continue;
			}
		}

		tls = (pcpp::ssl_tls_record_layer*)y.m_data;
		tls_payload = (uint8_t*)(y.m_data + sizeof(pcpp::ssl_tls_record_layer));
		prev_len = 0;

		while (pkt_length != 0)
		{
			u_int l = _byteswap_ushort(tls->length);

			if (l > pkt_length)
			{
				// Add package to Builder
				builder.AddPackage(y, true, l, prev_len);
				reassemble = true;
				break;
			}

			if (tls->recordType == pcpp::SSL_HANDSHAKE)
			{
				TlsMessages.push_back(MyTLSMessage(y, tls, tls_payload));
			}
			pkt_length -= sizeof(pcpp::ssl_tls_record_layer) + l;
			tls = (pcpp::ssl_tls_record_layer*)(tls_payload + l);
			tls_payload = (uint8_t*)(tls_payload + sizeof(pcpp::ssl_tls_record_layer) + l);
			prev_len += l + sizeof(pcpp::ssl_tls_record_layer);
			if (pkt_length > 1600)
			{
				std::cout << "[!] Something went wrong in normal packet handle" << std::endl;
				break;
			}
		}
	}

	// remove the connection from the connection manager
	connMgr->erase(iter);

	if (TlsMessages.size() == 0)
		return;

	std::cout << "[+] Connection to '" << connectionData.dstIP.toString() << "' end. Process build TLS Messages of this connection ..." << std::endl;
	std::cout << "[+] Building TLS Messages finished. Found " << TlsMessages.size() << " TLS Messages" << std::endl;

	std::vector<X509*> certChain;
	std::cout << "[+] Extract Certificate Message out of the messages and map this to m_trustedCertificatesListCount" << std::endl;
	
	int countMatch = 0;
	bool matchCertificate = false;
	bool matchSubject = false;
	bool certMessageExists = false;

	// Extract certificate chain of this connection
	for (MyTLSMessage msg : TlsMessages)
	{
		if (msg.IsCertificateMessage())
		{
			std::cout << "[+] Found certificate Message" << std::endl;
			certMessageExists = true;
			countCertificateMessagePerConnection++;

			msg.ExtractCertificateInfos(&certChain);
			if (certChain.size() == 0)
				continue;

			// Get the last Cert of the chain, -> should be the root cert
			X509* rootCert = certChain.back();
			int index = 0;
			std::cout << "[+] Search certificate with subject: " << X509_NAME_oneline(X509_get_subject_name(rootCert), NULL, 0) << std::endl;
			for (std::pair<int, X509*> &pair : m_trustedCertificateListCount)
			{
				if(verbose)
					std::cout << "  [*] Test certificate with subject: " << X509_NAME_oneline(X509_get_subject_name(pair.second), NULL, 0) << std::endl;

				if (X509_cmp(rootCert,pair.second) == 0) {
					countMatch++;
					matchCertificate = true;
					m_trustedCertificateListCountValues.at(index)++;
					std::cout << "============================ Matched Certificates ============================" << std::endl;
					std::cout << X509_NAME_oneline(X509_get_subject_name(rootCert), NULL, 0) << std::endl;
					std::cout << X509_NAME_oneline(X509_get_subject_name(pair.second), NULL, 0) << std::endl;
					std::cout << "==============================================================================" << std::endl;
				}
				index++;
				
				/* Going to in reasearch why some certificates are regularly different but the subject fits */
				if (verbose)
				{

					std::string searchSubj = X509_NAME_oneline(X509_get_subject_name(rootCert), NULL, 0);
					std::string currentSub = X509_NAME_oneline(X509_get_subject_name(pair.second), NULL, 0);

					if (searchSubj.compare(currentSub) == 0)
					{
						matchSubject = true;
						std::cout << "======================= Matched Subjects =======================" << std::endl;
						std::cout << X509_NAME_oneline(X509_get_subject_name(rootCert), NULL, 0) << std::endl;
						std::cout << X509_NAME_oneline(X509_get_subject_name(pair.second), NULL, 0) << std::endl;
						std::cout << "====================================================================" << std::endl;
					}
				}
			}
			
			certChain.clear();
		}
	}
	
	std::cout << "[+] Extracting finished" << std::endl;
	if (!certMessageExists)
	{
		std::cout << "[-] No Certificate Message found." << std::endl;
		std::cout << "****************************************** End Connection Callback finished ******************************************" << std::endl;
		return;
	}

	if (matchCertificate) 
	{
		countMatchCert++;
		std::cout << "[+] Certificate found" << std::endl;
	}
	else {
		countCertNotExist++;
		std::cout << "[!] The Certificate don't exist on the windows certificate store! This is bad" << std::endl;
	}
	if (matchSubject && verbose) 
	{
		countMatchSubj++;
		std::cout << "[+] Subject found but no certificate fits" << std::endl;
	}
	std::cout << "****************************************** End Connection Callback finished ******************************************" << std::endl;
}

/**
 * Go over all interfaces and output their names
 */
void listInterfaces()
{
	const std::vector<pcpp::PcapLiveDevice*>& devList = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDevicesList();

	printf("\nNetwork interfaces:\n");
	for (std::vector<pcpp::PcapLiveDevice*>::const_iterator iter = devList.begin(); iter != devList.end(); iter++)
	{
		printf("    -> Name: '%s'   IP address: %s\n", (*iter)->getName(), (*iter)->getIPv4Address().toString().c_str());
	}
	exit(0);
}

/**
 * The callback to be called when application is terminated by ctrl-c. Stops the endless while loop
 */
static void onApplicationInterrupted(void* cookie)
{
	bool* shouldStop = (bool*)cookie;
	*shouldStop = true;
}

/**
 * packet capture callback - called whenever a packet arrives on the live device (in live device capturing mode)
 */
static void onPacketArrives(pcpp::RawPacket* packet, pcpp::PcapLiveDevice* dev, void* tcpReassemblyCookie)
{
	// get a pointer to the TCP reassembly instance and feed the packet arrived to it
	pcpp::TcpReassembly* tcpReassembly = (pcpp::TcpReassembly*)tcpReassemblyCookie;
	tcpReassembly->reassemblePacket(packet);
}


/*
* called at beginning of the programm - read all Root CA certificates in the windows certificate store
*/
int readWindowsCAStore()
{
	int count = 0;
	HCERTSTORE hSysStore = NULL;
	PCCERT_CONTEXT pDesiredCert = NULL;
	if (hSysStore = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, NULL, CERT_SYSTEM_STORE_CURRENT_USER, L"Root")) // other common system sotres include "Root", "Trust", "MY", "CA"
	{
		// char pszNameString[256];
		printf("The system store was created successfully.\n");

		while (pDesiredCert = CertFindCertificateInStore(hSysStore, MY_ENCODING_TYPE, 0, CERT_FIND_ANY, NULL, pDesiredCert))
		{
			count++;
		
			X509* opensslCertificate = d2i_X509(nullptr, const_cast<unsigned char const**>(&pDesiredCert->pbCertEncoded), pDesiredCert->cbCertEncoded);
			if (opensslCertificate == nullptr)
			{
				printf("A certificate could not be converted");
			}
			else
			{
				// char* subj = X509_NAME_oneline(X509_get_subject_name(opensslCertificate), NULL, 0);
				// std::cout << "Subject: " << subj << std::endl << "============================================" << std::endl;
				m_trustedCertificateListCount.push_back(std::make_pair(0, opensslCertificate));
				m_trustedCertificateListCountValues.push_back(0);
			}
		}

		printf("Read %d Root CA's\n", count);
		if (CertCloseStore( hSysStore, CERT_CLOSE_STORE_CHECK_FLAG))
		{
			printf("The system store was closed successfully.\n");
		}
		else
		{
			printf("An error occurred during closing of the system store.\n");
		}
	}
	else
	{
		printf("An error occurred during creation of the system store!\n");
	}
	return count;
}


std::thread th_Figure1;

// A dummy function
void foo(figure_handle fh)
{
	/*figure_handle f = figure(false);
	f->title("Next Analysis relevant statical overview");
	auto ax = f->add_axes();
	f->size(800, 400);
	
	bar(ax, x);
	
	f->draw();*/
	std::vector<int> x = {5,4,8,1,6,15,7,8,9,10,11,12,13,14,15,16,17};
	auto ax = fh->add_subplot(4,3,2);
	ax->bar(x);
	
	//fh->touch();
}

// A dummy function
void boo(figure_handle fh)
{
	/*figure_handle f = figure(false);
	f->title("Next Analysis relevant statical overview");
	auto ax = f->add_axes();
	f->size(800, 400);

	bar(ax, x);

	f->draw();*/
	std::vector<int> x = { 5,4,8,1,6};
	auto ax = fh->add_subplot(4, 3, 9);
	ax->bar(x);

	//fh->touch();
}

// Maybe doing plotting in another thread for update on live captureing with a callback
void ConfigTHFigure1()
{
	auto fh = figure();
	fh->ion();
	fh->size(1200, 860);

	std::vector<std::string> x_labels;
	//x_labels.push_back("");
	std::vector<int> value;
	for (auto p : m_trustedCertificateListCount)
	{
		std::string sub = X509_NAME_oneline(X509_get_subject_name(p.second), NULL, 0);
		std::vector<std::string> part_sub;
		boost::split(part_sub, sub, [](char c) { return c == '/'; });
		x_labels.push_back(part_sub.back().substr(3));
		// m_trustedCertificateListCountValues.push_back(p.first);
	}

	std::vector<double> ticks;
	for (int i = 1; i < m_trustedCertificateListCount.size()+1; i++) {
		ticks.push_back(i);
		//std::cout << "Subject -> " << x_labels[i] << std::endl;
	}
	
	auto ax = fh->add_axes();
	ax->bar(m_trustedCertificateListCountValues);
	ax->xticks(ticks);
	ax->xticklabels(x_labels);
	ax->xtickangle(90);
	ax->ylabel("Frequency");
	fh->touch();

}

void printOverview()
{
	std::cout << "======================================= Overview =======================================" << std::endl;
	std::cout << "[+] Messages Ready : " << messagesReady << std::endl;
	std::cout << "[+] Messages Start Conn seen: " << messagesStartCon << std::endl;
	std::cout << "[+] Messages End Conn seen: " << messagesEndcon << ", of these are " << countCertificateMessagePerConnection << " Certificates found" << std::endl;
	std::cout << "[+] Count certificate match: " << countMatchCert << std::endl;
	std::cout << "[+] Count certificate not found in windows certificate store: " << countCertNotExist << std::endl;
	if(verbose) 
		std::cout << "[+] Only the Subject matched nor the Certificate: " << countMatchSubj << std::endl;

	std::cout << "========================================================================================" << std::endl;
}

/**
 * The method responsible for TCP reassembly on live traffic
 */
void doOnLiveTraffic(pcpp::PcapLiveDevice* dev, pcpp::TcpReassembly& tcpReassembly)
{
	// try to open device
	if (!dev->open())
		printf("Cannot open interface");

	std::cout << "[+] Start Process to create figures..." << std::endl;
	th_Figure1 = std::thread(ConfigTHFigure1);

	printf("Starting packet capture on '%s'...\n", dev->getIPv4Address().toString().c_str());

	// start capturing packets. Each packet arrived will be handled by onPacketArrives method
	dev->startCapture(onPacketArrives, &tcpReassembly);

	// register the on app close event to print summary stats on app termination
	bool shouldStop = false;
	pcpp::ApplicationEventHandler::getInstance().onApplicationInterrupted(onApplicationInterrupted, &shouldStop);

	// run in an endless loop until the user presses ctrl+c
	while (!shouldStop)
		PCAP_SLEEP(1);

	// stop capturing and close the live device
	dev->stopCapture();
	dev->close();

	// close all connections which are still opened
	tcpReassembly.closeAllConnections();

	printf("Done! processed %d connections\n", (int)tcpReassembly.getConnectionInformation().size());
	printOverview();
}

/**
 * The method responsible for TCP reassembly on pcap/pcapng files
 */
void doTcpReassemblyOnPcapFile(std::string fileName, pcpp::TcpReassembly& tcpReassembly)
{
	pcpp::IFileReaderDevice* reader = pcpp::IFileReaderDevice::getReader(fileName.c_str());
	if (!reader->open())
	{
		printf("Error opening the pcap file\n");
		return;
	}

	std::cout << "[+] Start Process to create figures..." << std::endl;
	th_Figure1 = std::thread(ConfigTHFigure1);

	std::cout << "[+] Start reassembling packets..." << std::endl;
	pcpp::RawPacket rawPacket;
	while (reader->getNextPacket(rawPacket))
	{
		tcpReassembly.reassemblePacket(&rawPacket);
	}
	std::cout << "[+] Closing Connections that are not ended manually" << std::endl;
	tcpReassembly.closeAllConnections();
	std::cout << "[+] Reassembling finished" << std::endl;

	reader->close();
	delete reader;

	printOverview();
	// ConfigTHFigure1();

}

int main(int argc, char* argv[])
{
	std::string interfaceNameOrIP;
	std::string filename;

	po::options_description desc("Allowed options");
	desc.add_options()
		("help", "view the help message")
		("verbose", "Enable verbose mode")
		("interface", po::value<std::string>(&interfaceNameOrIP), "IP for live capturing")
		("file", po::value<std::string>(&filename), "Filename of the pcap for analysing");

	po::variables_map vm;
	po::store(po::parse_command_line(argc, argv, desc), vm);
	po::notify(vm);

	// create the object which manages info on all connections
	TcpReassemblyConnMgr connMgr;
	pcpp::TcpReassembly tcpReassembly(tcpReassemblyMsgReadyCallback, &connMgr, tcpReassemblyConnectionStartCallback, tcpReassemblyConnectionEndCallback);
	
	if (vm.count("help"))
	{
		std::cout << desc << std::endl;
		return 1;
	}
	if (vm.size() == 0) {
		std::cout << desc << std::endl;
		return 1;
	}
	if (vm.count("verbose"))
	{
		verbose = true;
	}

	if (vm.count("interface"))
	{
		int countCertInStore = readWindowsCAStore();
		if (countCertInStore <= 0)
		{
			std::cout << "The give windows certificate store can't load certificates. " << std::endl;
			return 1;
		}

		std::cout << "Start captureing on interface: " << vm["interface"].as<std::string>() << std::endl;
		pcpp::PcapLiveDevice* dev = NULL;
		pcpp::IPv4Address interfaceIP(interfaceNameOrIP);
		if (interfaceIP.isValid())
		{
			dev = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp(interfaceIP);
			if (dev == NULL)
				std::cout << "Couldn't find interface by provided IP" << std::endl;
		}
		else
		{
			dev = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByName(interfaceNameOrIP);
			if (dev == NULL)
				std::cout << "Couldn't find interface by provided name" << std::endl;
		}

		// start capturing packets and do TCP reassembly
		doOnLiveTraffic(dev, tcpReassembly);
		
	}
	else if (vm.count("file"))
	{
		int countCertInStore = readWindowsCAStore();
		if (countCertInStore <= 0)
		{
			std::cout << "The give windows certificate store can't load certificates. " << std::endl;
			return 1;
		}

		std::cout << "Start analysing file: " << vm["file"].as<std::string>() << std::endl;
		doTcpReassemblyOnPcapFile(filename, tcpReassembly);

	}
	
	std::cout << "Programm end!" << std::endl;
	std::cout << "Wait for figures ending..." << std::endl;
	th_Figure1.join();
	std::cout << "Press enter to return and quit the figures... " << std::endl;
	getchar();

	return 0;
}