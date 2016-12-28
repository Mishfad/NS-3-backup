/* A sample program to test our understanding level of NS-3
 * by implementing a sample manet system
 */

#include <fstream>
#include <iostream>
#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/mobility-module.h"
#include "ns3/wifi-module.h"
#include "ns3/aodv-module.h"
#include "ns3/gnuplot.h"
//#include "ns3/dsdv-module.h"
//#include "ns3/dsr-module.h"
#include "ns3/applications-module.h"

#include "ns3/netanim-module.h"

using namespace ns3;

class MyApp : public Application
{
public:

  MyApp ();
  virtual ~MyApp();

  void Setup (Ptr<Socket> socket, Address address, uint32_t packetSize, uint32_t nPackets, DataRate dataRate);

private:
  virtual void StartApplication (void);
  virtual void StopApplication (void);

  void ScheduleTx (void);
  void SendPacket (void);

  Ptr<Socket>     m_socket;
  Address         m_peer;
  uint32_t        m_packetSize;
  uint32_t        m_nPackets;
  DataRate        m_dataRate;
  EventId         m_sendEvent;
  bool            m_running;
  uint32_t        m_packetsSent;
};

MyApp::MyApp ()
  : m_socket (0),
    m_peer (),
    m_packetSize (0),
    m_nPackets (0),
    m_dataRate (0),
    m_sendEvent (),
    m_running (false),
    m_packetsSent (0)
{
}

MyApp::~MyApp()
{
  m_socket = 0;
}

void
MyApp::Setup (Ptr<Socket> socket, Address address, uint32_t packetSize, uint32_t nPackets, DataRate dataRate)
{
  m_socket = socket;
  m_peer = address;
  m_packetSize = packetSize;
  m_nPackets = nPackets;
  m_dataRate = dataRate;
}

void
MyApp::StartApplication (void)
{
  m_running = true;
  m_packetsSent = 0;
  m_socket->Bind ();
  m_socket->Connect (m_peer);
  SendPacket ();
}

void
MyApp::StopApplication (void)
{
  m_running = false;

  if (m_sendEvent.IsRunning ())
    {
      Simulator::Cancel (m_sendEvent);
    }

  if (m_socket)
    {
      m_socket->Close ();
    }
}

void
MyApp::SendPacket (void)
{
  Ptr<Packet> packet = Create<Packet> (m_packetSize);
  m_socket->Send (packet);

  if (++m_packetsSent < m_nPackets)
    {
      ScheduleTx ();
    }
}

void
MyApp::ScheduleTx (void)
{
  if (m_running)
    {
      Time tNext (Seconds (m_packetSize * 8 / static_cast<double> (m_dataRate.GetBitRate ())));
      m_sendEvent = Simulator::Schedule (tNext, &MyApp::SendPacket, this);
    }
}

int main(int argc, char **argv) {

	int no_of_nodes=5;
	std::string phyMode ("DsssRate11Mbps");
	int txp=1;
	int node_speed=20;	// in m/s
	int node_pause=0;

	// create node container and nodes
	NodeContainer manet_node_container;
	manet_node_container.Create(no_of_nodes);

	//Creation of wifi channel, device and channel
//	#######################################################
//	NEED TO PROPERLY KNOW WHAT IS HAPPENING WITH THE WIFI

	WifiHelper wifi;
	wifi.SetStandard(WIFI_PHY_STANDARD_80211ac);

	YansWifiPhyHelper wifi_phy=YansWifiPhyHelper::Default();
	YansWifiChannelHelper wifi_channel;
	wifi_channel.SetPropagationDelay("ns3::ConstantSpeedPropagationDelayModel");
	wifi_channel.AddPropagationLoss("ns3::FriisPropagationLossModel");
	wifi_phy.SetChannel(wifi_channel.Create());

	WifiMacHelper wifi_mac;
	wifi.SetRemoteStationManager("ns3::ConstantRateWifiManager","DataMode",StringValue (phyMode),
                                "ControlMode",StringValue (phyMode));
	wifi_phy.Set ("TxPowerStart",DoubleValue (txp));
	wifi_phy.Set ("TxPowerEnd", DoubleValue (txp));
	wifi_mac.SetType ("ns3::AdhocWifiMac");

	NetDeviceContainer manet_device = wifi.Install(wifi_phy,wifi_mac,manet_node_container);

	//Mobility
	MobilityHelper manet_mobility;
	int64_t stream_index=0;

	ObjectFactory pos;
	pos.SetTypeId("ns3::RandomRectanglePositionAllocator");
	pos.Set("X",StringValue("ns3::UniformRandomVariable[Min=0.0|Max=200]"));
	pos.Set("Y",StringValue("ns3::UniformRandomVariable[Min=0.0|Max=200]"));

	Ptr<PositionAllocator> taPositionAlloc = pos.Create ()->GetObject<PositionAllocator> ();
	stream_index += taPositionAlloc->AssignStreams (stream_index);

	std::stringstream ssSpeed;
	ssSpeed << "ns3::UniformRandomVariable[Min=0.0|Max=" << node_speed << "]";
	std::stringstream ssPause;
	ssPause << "ns3::ConstantRandomVariable[Constant=" << node_pause << "]";
	manet_mobility.SetMobilityModel ("ns3::RandomWaypointMobilityModel",
	                                  "Speed", StringValue (ssSpeed.str ()),
	                                  "Pause", StringValue (ssPause.str ()),
	                                  "PositionAllocator", PointerValue (taPositionAlloc));

	manet_mobility.SetPositionAllocator(taPositionAlloc);
	manet_mobility.Install(manet_node_container);
	stream_index+= manet_mobility.AssignStreams(manet_node_container,stream_index);

	// Internet stack, IPv4 address, interfaces

	AodvHelper aodv_routing;
	Ipv4ListRoutingHelper list;
	InternetStackHelper internet_stack;

	list.Add(aodv_routing,50);
	internet_stack.SetRoutingHelper(list);
	internet_stack.Install(manet_node_container);

	Ipv4AddressHelper manet_ip_address;
	manet_ip_address.SetBase("10.1.1.0","255.255.255.0");
	Ipv4InterfaceContainer manet_ip_interface;
	manet_ip_address.Assign(manet_device);

//	configuring the node 0 as packet sink (in other words, configure as destination)
    uint16_t sinkPort = 8080;
	Address sinkAddress (InetSocketAddress (manet_ip_interface.GetAddress (0), sinkPort));
	PacketSinkHelper packetSinkHelper ("ns3::TcpSocketFactory", InetSocketAddress (Ipv4Address::GetAny (), sinkPort));
	ApplicationContainer sinkApps = packetSinkHelper.Install (manet_node_container.Get (0));
	sinkApps.Start (Seconds (0.));
	sinkApps.Stop (Seconds (20.));

	Ptr<Socket> ns3TcpSocket = Socket::CreateSocket (manet_node_container.Get (0), TcpSocketFactory::GetTypeId ());

	Ptr<MyApp> app = CreateObject<MyApp> ();
	app->Setup (ns3TcpSocket, sinkAddress, 1040, 1000, DataRate ("1Mbps"));
	manet_node_container.Get (0)->AddApplication (app);
	app->SetStartTime (Seconds (1.));
	app->SetStopTime (Seconds (20.));

	Simulator::Stop (Seconds (20));
	Simulator::Run ();
	Simulator::Destroy ();
}

