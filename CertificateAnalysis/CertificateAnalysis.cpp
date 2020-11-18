
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
int countMatchCertIssuer = 0;
int countCertNotExist = 0;
int countMatchCert = 0;
int countMatchIssuer = 0;

using namespace std;
using namespace matplot;
namespace po = boost::program_options;

// typedef representing the connection manager and its iterator
typedef map<uint32_t, vector<TcpReassemblyData>> TcpReassemblyConnMgr;
typedef map<uint32_t, vector<TcpReassemblyData>>::iterator TcpReassemblyConnMgrIter;

/* Figure 1 Values */
vector<pair<int, X509*>> m_trustedCertificateListCount;
vector<vector<int>> m_fig1Values;

/* Figure 2 Values */
vector<int> m_fig2CertCount;
vector<tm> m_fig2Values;
// vector<time_t> m_fig2ValuesSec;

/* Figures init */
auto fh1 = figure(true);
auto fh2 = figure(true);

void UpdateFigures()
{
	// Figure 1 - Bar
	fh1->current_axes()->bar(m_fig1Values);
	fh1->current_axes()->draw();

	// Figure 2 - not finished yet
	/*fh2->current_axes()->plot(m_fig2Values);
	fh2->current_axes()->draw();*/
}

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
		vector<TcpReassemblyData> tmp;
		connMgr->insert(make_pair(tcpData.getConnectionData().flowKey, tmp));
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
		vector<TcpReassemblyData> tmp;
		connMgr->insert(make_pair(connectionData.flowKey, tmp));
	}
}

/**
 * The callback being called by the TCP reassembly module whenever a connection is ending. This method removes the connection from the connection manager and writes the metadata file if requested
 * by the user
 */
static void tcpReassemblyConnectionEndCallback(const pcpp::ConnectionData& connectionData, pcpp::TcpReassembly::ConnectionEndReason reason, void* userCookie)
{
	messagesEndcon++;
	vector<MyTLSMessage> TLSMessageList;

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
				builder.CreateTLSMessage(&TLSMessageList);
				builder.Clear();
				reassemble = false;
				continue;
			}
			else
			{
				builder.CreateTLSMessage(&TLSMessageList);
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
						TLSMessageList.push_back(MyTLSMessage(y, tls, tls_payload));
					}
					pkt_length -= sizeof(pcpp::ssl_tls_record_layer) + l;
					tls = (pcpp::ssl_tls_record_layer*)(tls_payload + l);
					tls_payload = (uint8_t*)(tls_payload + sizeof(pcpp::ssl_tls_record_layer) + l);
					curManageIndex += l + sizeof(pcpp::ssl_tls_record_layer);
					if (pkt_length > 1600)
					{
						cout << "[!] Something went wrong in handle rest of the packet" << endl;
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
				TLSMessageList.push_back(MyTLSMessage(y, tls, tls_payload));
			}
			pkt_length -= sizeof(pcpp::ssl_tls_record_layer) + l;
			tls = (pcpp::ssl_tls_record_layer*)(tls_payload + l);
			tls_payload = (uint8_t*)(tls_payload + sizeof(pcpp::ssl_tls_record_layer) + l);
			prev_len += l + sizeof(pcpp::ssl_tls_record_layer);
			if (pkt_length > 1600)
			{
				cout << "[!] Something went wrong in normal packet handle" << endl;
				break;
			}
		}
	}

	// remove the connection from the connection manager
	connMgr->erase(iter);

	if (TLSMessageList.size() == 0)
		return;

	cout << "[+] Connection to '" << connectionData.dstIP.toString() << "' end. Process build TLS Messages of this connection ..." << endl;
	cout << "[+] Building TLS Messages finished. Found " << TLSMessageList.size() << " TLS Messages" << endl;

	vector<X509*> certChain;
	cout << "[+] Extract Certificate Message" << endl;
	
	int countMatch = 0;
	bool matchCertificate = false;
	bool matchIssuer = false;
	bool certMessageExists = false;
	vector<int> removeableMessages;
	// Extract certificate chain of this connection
	for (MyTLSMessage msg : TLSMessageList)
	{
		if (msg.IsCertificateMessage())
		{
			cout << "[+] Found certificate Message" << endl;
			certMessageExists = true;
			countCertificateMessagePerConnection++;

			msg.ExtractCertificateInfos(&certChain);
			if (certChain.size() == 0)
				continue;

			// Get the last Cert of the chain, -> should be the root cert
			X509* rootCert = certChain.back();
			int index = 0;
			cout << "[+] Search certificate with Issuer: " << X509_NAME_oneline(X509_get_issuer_name(rootCert), NULL, 0) << endl;
			for (pair<int, X509*> &pair : m_trustedCertificateListCount)
			{
				if(verbose)
					cout << "  [*] Test certificate with Issuer: " << X509_NAME_oneline(X509_get_issuer_name(pair.second), NULL, 0) << endl;

				// Maybe this isn't required. 
				if (X509_cmp(rootCert,pair.second) == 0) {
					countMatch++;
					matchCertificate = true;
					m_fig1Values.at(0).at(index)++;
					cout << "============================ Matched Certificates ============================" << endl;
					cout << X509_NAME_oneline(X509_get_issuer_name(rootCert), NULL, 0) << endl;
					cout << X509_NAME_oneline(X509_get_issuer_name(pair.second), NULL, 0) << endl;
					cout << "==============================================================================" << endl;
				}

				string searchIssuer = X509_NAME_oneline(X509_get_issuer_name(rootCert), NULL, 0);
				string currentIssuer = X509_NAME_oneline(X509_get_issuer_name(pair.second), NULL, 0);

				if (searchIssuer.compare(currentIssuer) == 0)
				{
					matchIssuer = true;

					if (m_fig1Values.at(1).at(index) == 0)
					{
						// Certificate Message found and not seen before
						// Get timestamp of the connection start time and add this to a list
						const time_t arrival = connectionData.startTime.tv_sec;
						// m_fig2ValuesSec.push_back(arrival);
						struct tm arr_tm;
						localtime_s(&arr_tm, &arrival);
						m_fig2Values.push_back(arr_tm);
					}

					m_fig1Values.at(1).at(index)++;
					cout << "========================= Matched Issuer =========================" << endl;
					cout << searchIssuer << endl;
					cout << currentIssuer << endl;
					cout << "==================================================================" << endl;
					
					break;
				}
				
				index++;
			}
			
			certChain.clear();
		}
	}
		
	cout << "[+] Extracting finished" << endl;
	if (!certMessageExists)
	{
		cout << "[-] No Certificate Message found." << endl;
		cout << "****************************************** End Connection Callback finished ******************************************" << endl;
		return;
	}

	if (matchCertificate && matchIssuer) 
	{
		countMatchCertIssuer++;
		countMatchIssuer++;
		countMatchCert++;
		cout << "[+] Certificate found. Issuer and certificate fits" << endl;
	}
	else 
	{
		if (matchCertificate) 
		{
			countMatchCert++;
			cout << "[+] Certificate found" << endl;
		}
		else if (matchIssuer)
		{
			countMatchIssuer++;
			cout << "[+] Issuer match found but certificate don't fit" << endl;
		}
		else {
			countCertNotExist++;
			cout << "[!] The Certificate don't exist on the windows certificate store! This is bad" << endl;
		}
	}

	if (messagesEndcon % 100 == 0)
	{
		UpdateFigures();
	}
	cout << "****************************************** End Connection Callback finished ******************************************" << endl;
}

/**
* Static method for comparing dates. Used by the figure2 plot function.
*/
static int cmp_dates_descend(const void* d1, const void* d2)
{
	struct tm date_1 = *(const struct tm*)d1;
	struct tm date_2 = *(const struct tm*)d2;

	double d = difftime(mktime(&date_1), mktime(&date_2));

	return (d > 0) - (d < 0);
}

/**
 * Go over all interfaces and output their names
 */
void listInterfaces()
{
	const vector<pcpp::PcapLiveDevice*>& devList = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDevicesList();

	printf("\nNetwork interfaces:\n");
	for (vector<pcpp::PcapLiveDevice*>::const_iterator iter = devList.begin(); iter != devList.end(); iter++)
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
		vector<int> certTmp;
		vector<int> issuerTmp;
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
				// cout << "Subject: " << subj << endl << "============================================" << endl;
				m_trustedCertificateListCount.push_back(make_pair(0, opensslCertificate));
				certTmp.push_back(0);
				issuerTmp.push_back(0);
				//m_figValuesCertMatch.push_back(0);
				//m_figValuesIssuerMatch.push_back(0);
			}
		}
		m_fig1Values.push_back(certTmp);
		m_fig1Values.push_back(issuerTmp);

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

/**
* Figure1 beschreibt die Häufigkeit der verwendeten zertifikate auf basis von übereinstimmender Zertifikaten und falls es kein Wurzelzertifikat ist
* wird über den Issuer der Root Zertifikates der CN des konkreten Wurzelzertifikates extrahiert
* 
* Diese statistik wird immer wieder aktualisiert und somit am Anfang des programms konfiguriert
*/
void ConfigFigure1()
{
	fh1->title("Verwendete Zertifikate");
	fh1->size(1200, 700);

	vector<string> x_labels;
	vector<int> value;
	for (auto p : m_trustedCertificateListCount)
	{
		string sub = X509_NAME_oneline(X509_get_subject_name(p.second), NULL, 0);
		vector<string> part_sub;
		boost::split(part_sub, sub, [](char c) { return c == '/'; });
		x_labels.push_back(part_sub.back().substr(3));
	}

	vector<double> ticks;
	for (int i = 1; i < m_trustedCertificateListCount.size()+1; i++) {
		ticks.push_back(i);
	}
	
	auto ax = fh1->add_subplot(3, 1, 0);

	ax->bar(m_fig1Values);

	ax->xticks(ticks);
	ax->xticklabels(x_labels);
	ax->xtickangle(90);
	ax->ylabel("Frequency");

	vector<string> lgd_titels = { "Something A", "Something B" };
	ax->legend(lgd_titels);

	ax->draw();

}

/**
* Figure2 wird erst am ende geplottet, da die achsenabstände über die zeit sich verändern und das zur folge hat dass die axen neu konfiguriert werden müssen
* 
* Figure2 beschreibt die zeitbasierte Häufigkeit. Wann stagniert es das neue Wurzelzertifikate benutzt werden.
* Es wird prozentual der anteil verwendeter CA's berechnet und im zusammenhang mit einer zeitachse angezeigt.
*/
void PlotFigure2()
{
	cout << " *************************** Creating Plot time based frequency  *************************** " << endl;
	// Sorting the timestamps
	qsort(&m_fig2Values[0], m_fig2Values.size(), sizeof tm, cmp_dates_descend);

	/*for (auto t : m_fig2Values)
	{
		char buff[100];
		strftime(buff, 100, "%Y-%m-%d %H:%M:%S.000", &t);
		cout << buff << endl;
	}
	cout << endl;*/

	m_fig2CertCount.push_back(0);
	
	tm t_begin = m_fig2Values.front();
	tm t_end = m_fig2Values.back();

	// calculate the timespan of first and last for the ticks in the plot
	cout << "[*] Calculate Timespan of the first and last seen certificate messsage" << endl;
	time_t t_span = difftime(mktime(&t_end), mktime(&t_begin));

	if (verbose) {
		char front[100];
		char back[100];
		strftime(front, 100, "%Y-%m-%d %H:%M:%S.000", &t_begin);
		strftime(back, 100, "%Y-%m-%d %H:%M:%S.000", &t_end);
		cout << "[*] Time first seen: " << front << endl;
		cout << "[*] Time last seen: " << back << endl;
		cout << "[*] Time difference in seconds: " << t_span << endl;
	}
	
	// split into 10 pieces
	time_t span_sec = t_span / 100;

	time_t start_time_span = mktime(&m_fig2Values[0]);
	time_t end_time_span = start_time_span + span_sec;
	int add_counter = 0;
	vector<string> lbl_ticks;
	lbl_ticks.push_back("");
	bool finish = false;
	for (int i = 0; i < m_fig2Values.size(); i++)
	{
		tm start_time;
		tm cmp_end_time_span;
		localtime_s(&start_time, &start_time_span);
		localtime_s(&cmp_end_time_span, &end_time_span);
		
		char buff_start[100];
		char buff_end[100];
		strftime(buff_start, 100, "%Y-%m-%d %H:%M:%S.000", &start_time);
		strftime(buff_end, 100, "%Y-%m-%d %H:%M:%S.000", &cmp_end_time_span);
		lbl_ticks.push_back(buff_start);

		if (finish)
		{
			// lbl_ticks.push_back(buff_end);
			break;
		}
		if (verbose) {
			cout << "[*] Count stamps from " << buff_start << " till: " << buff_end << endl;
		}

		for (int j = i; j < m_fig2Values.size(); j++)
		{
			if (cmp_dates_descend(&cmp_end_time_span, &m_fig2Values[j]) > 0)
			{
				if (verbose) {
					char buff[100];
					strftime(buff, 100, "%Y-%m-%d %H:%M:%S.000", &m_fig2Values[j]);
					cout << "[*] In time: " << buff << endl;
				}
				add_counter++;
				if (j == m_fig2Values.size() - 1)
				{
					m_fig2CertCount.push_back(add_counter);
					finish = true;
				}
			}
			else
			{
				m_fig2CertCount.push_back(add_counter);
				i = j;
				i--;
				// add_counter = 0;
				break;
			}
		}
	
		start_time_span = end_time_span;
		end_time_span += span_sec;
	}

	fh2->title("Zeitbasierte stagnation der Root CA's");
	fh2->size(1000, 600);

	vector<double> ticks;
	for (int u = 0; u < lbl_ticks.size(); u++)
		ticks.push_back(u);

	auto ax = fh2->add_subplot(2, 1, 0);
	ax->plot(m_fig2CertCount);
	
	ax->xticks(ticks);
	ax->xticklabels(lbl_ticks);
	ax->xtickangle(90);
	
	ax->ylim({ 0, (double)add_counter + 1 });
	ax->ylabel("Kumulative Root CA Count");

	// which plot does fit best???

	cout << " *************************** Creating Plot time based frequency finsihed  *************************** " << endl;
	ax->draw();
	

}

void printOverview()
{
	cout << "======================================= Overview =======================================" << endl;
	cout << "[+] Messages Ready : " << messagesReady << endl;
	cout << "[+] Messages Start Conn seen: " << messagesStartCon << endl;
	cout << "[+] Messages End Conn seen: " << messagesEndcon << ", of these are " << countCertificateMessagePerConnection << " Certificates found" << endl;
	cout << "[+] Count certificate match: " << countMatchCert << endl;
	cout << "	means that these Domains are signed by a conrete RootCA certificate" << endl;
	cout << "[+] Count certificate not found in windows certificate store: " << countCertNotExist << endl;
	if(verbose) 
		cout << "[+] Only the Issuer matched: " << countMatchIssuer << endl;
	cout << "========================================================================================" << endl;
}

/**
 * The method responsible for TCP reassembly on live traffic
 */
void doOnLiveTraffic(pcpp::PcapLiveDevice* dev, pcpp::TcpReassembly& tcpReassembly)
{
	// try to open device
	if (!dev->open())
		printf("Cannot open interface");

	// Initialise all Figures
	ConfigFigure1();

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

	// update the figure last time
	UpdateFigures();
	PlotFigure2();

	printOverview();
}

/**
 * The method responsible for TCP reassembly on pcap/pcapng files
 */
void doTcpReassemblyOnPcapFile(string fileName, pcpp::TcpReassembly& tcpReassembly)
{
	pcpp::IFileReaderDevice* reader = pcpp::IFileReaderDevice::getReader(fileName.c_str());
	if (!reader->open())
	{
		printf("Error opening the pcap file\n");
		return;
	}

	// Initialise all Figures
	ConfigFigure1();
	// ConfigTHFigure2();

	cout << "[+] Start reassembling packets..." << endl;
	pcpp::RawPacket rawPacket;
	while (reader->getNextPacket(rawPacket))
	{
		tcpReassembly.reassemblePacket(&rawPacket);
	}
	cout << "[+] Closing Connections that are not ended manually" << endl;
	tcpReassembly.closeAllConnections();
	cout << "[+] Reassembling finished" << endl;

	reader->close();
	delete reader;

	UpdateFigures();
	PlotFigure2();
	
	printOverview();
}

int main(int argc, char* argv[])
{
	string interfaceNameOrIP;
	string filename;
	bool file = false;

	po::options_description desc("Allowed options");
	desc.add_options()
		("help", "view the help message")
		("verbose", "Enable verbose mode")
		("interface", po::value<string>(&interfaceNameOrIP), "IP for live capturing")
		("file", po::value<string>(&filename), "Filename of the pcap for analysing");

	po::variables_map vm;
	po::store(po::parse_command_line(argc, argv, desc), vm);
	po::notify(vm);

	// create the object which manages info on all connections
	TcpReassemblyConnMgr connMgr;
	pcpp::TcpReassembly tcpReassembly(tcpReassemblyMsgReadyCallback, &connMgr, tcpReassemblyConnectionStartCallback, tcpReassemblyConnectionEndCallback);
	
	if (vm.count("help"))
	{
		cout << desc << endl;
		return 1;
	}
	if (vm.size() == 0) {
		cout << desc << endl;
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
			cout << "The give windows certificate store can't load certificates. " << endl;
			return 1;
		}

		cout << "Start captureing on interface: " << vm["interface"].as<string>() << endl;
		pcpp::PcapLiveDevice* dev = NULL;
		pcpp::IPv4Address interfaceIP(interfaceNameOrIP);
		if (interfaceIP.isValid())
		{
			dev = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp(interfaceIP);
			if (dev == NULL)
				cout << "Couldn't find interface by provided IP" << endl;
		}
		else
		{
			dev = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByName(interfaceNameOrIP);
			if (dev == NULL)
				cout << "Couldn't find interface by provided name" << endl;
		}

		// start capturing packets and do TCP reassembly
		doOnLiveTraffic(dev, tcpReassembly);
		
	}
	else if (vm.count("file"))
	{
		file = true;
		int countCertInStore = readWindowsCAStore();
		if (countCertInStore <= 0)
		{
			cout << "The give windows certificate store can't load certificates. " << endl;
			return 1;
		}

		cout << "Start analysing file: " << vm["file"].as<string>() << endl;
		doTcpReassemblyOnPcapFile(filename, tcpReassembly);

	}
	
	cout << "Programm end!" << endl;
	show();

	return 0;
}