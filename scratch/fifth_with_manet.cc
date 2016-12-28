/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <fstream>
#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/applications-module.h"
#include "ns3/wifi-module.h"
#include "ns3/aodv-module.h"
#include "ns3/mobility-module.h"


using namespace ns3;


NS_LOG_COMPONENT_DEFINE ("FifthScriptExample");

// ===========================================================================
//
//         node 0                 node 1
//   +----------------+    +----------------+
//   |    ns-3 TCP    |    |    ns-3 TCP    |
//   +----------------+    +----------------+
//   |    10.1.1.1    |    |    10.1.1.2    |
//   +----------------+    +----------------+
//   | point-to-point |    | point-to-point |
//   +----------------+    +----------------+
//           |                     |
//           +---------------------+
//                5 Mbps, 2 ms
//
//
// We want to look at changes in the ns-3 TCP congestion window.  We need
// to crank up a flow and hook the CongestionWindow attribute on the socket
// of the sender.  Normally one would use an on-off application to generate a
// flow, but this has a couple of problems.  First, the socket of the on-off 
// application is not created until Application Start time, so we wouldn't be 
// able to hook the socket (now) at configuration time.  Second, even if we 
// could arrange a call after start time, the socket is not public so we 
// couldn't get at it.
//
// So, we can cook up a simple version of the on-off application that does what
// we want.  On the plus side we don't need all of the complexity of the on-off
// application.  On the minus side, we don't have a helper, so we have to get
// a little more involved in the details, but this is trivial.
//
// So first, we create a socket and do the trace connect on it; then we pass 
// this socket into the constructor of our simple application which we then 
// install in the source node.
// ===========================================================================
//
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
  uint8_t 		  m_buffer;

};

MyApp::MyApp ()
  : m_socket (0), 
    m_peer (), 
    m_packetSize (0), 
    m_nPackets (0), 
    m_dataRate (0), 
    m_sendEvent (), 
    m_running (false), 
    m_packetsSent (0),
	m_buffer(0)
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
  Ptr<Packet> packet = Create<Packet> (&m_buffer,m_packetSize);
  m_socket->Send (packet);
  NS_LOG_UNCOND(Simulator::Now().GetSeconds()<<"\tPacket number: "<<int(m_buffer));
  m_buffer++;

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

//static void
//CwndChange (uint32_t oldCwnd, uint32_t newCwnd)
//{
////  NS_LOG_UNCOND (Simulator::Now ().GetSeconds () << "\t" << newCwnd);
//}

static void
TransmitTrace(Ptr<const Packet> packet, Ptr<Ipv4> ipv4,  uint32_t num)
{
  uint8_t buffer;
  packet->CopyData(&buffer,1);
  NS_LOG_LOGIC (Simulator::Now ().GetSeconds () << "\t Transmit trace\t" << packet->GetUid() <<"\t"<<ipv4->GetInstanceTypeId()<<"\t"<<int(buffer));
}

static void
LocalDelivery(Ptr<OutputStreamWrapper> broadcast_stream,Ptr<OutputStreamWrapper> unicast_stream,std::string context,const Ipv4Header &header, Ptr<const Packet> packet, uint32_t num)
{
	uint8_t buffer;

	packet->CopyData(&buffer,1);
	if(header.GetDestination()=="10.1.1.255")
	{
		*broadcast_stream->GetStream()<<Simulator::Now ().GetSeconds ()<<","<<context<<",Source: "<<header.GetSource() <<",Destination: "<<header.GetDestination()<<"\n";
		NS_LOG_LOGIC(Simulator::Now ().GetSeconds ()<<"\t"<<context<<"\tSource: "<<header.GetSource() <<"\tDestination: "<<header.GetDestination() <<"\tPacket:"<<int(buffer));

	}
	else
	{
		*unicast_stream->GetStream()<<Simulator::Now ().GetSeconds ()<<","<<context<<",Source: "<<header.GetSource() <<",Destination: "<<header.GetDestination()<<"\n";
		NS_LOG_LOGIC(Simulator::Now ().GetSeconds ()<<"\t"<<context<<"\tSource: "<<header.GetSource() <<"\tDestination: "<<header.GetDestination()<<"\tPacket:"<<int(buffer));
	}
}

static void
RxDrop (Ptr<const Packet> p)
{
  NS_LOG_UNCOND ("RxDrop at " << Simulator::Now ().GetSeconds ());
}

int 
main (int argc, char *argv[])
{
	Packet::EnablePrinting();

  NodeContainer nodes;
  nodes.Create (15);

  // setting up wifi phy and channel using helpers
    WifiHelper wifi;
    wifi.SetStandard (WIFI_PHY_STANDARD_80211b);

    YansWifiPhyHelper wifiPhy =  YansWifiPhyHelper::Default ();
    YansWifiChannelHelper wifiChannel;
    wifiChannel.SetPropagationDelay ("ns3::ConstantSpeedPropagationDelayModel");
    wifiChannel.AddPropagationLoss ("ns3::FriisPropagationLossModel");
    wifiPhy.SetChannel (wifiChannel.Create ());

    // Add a mac and disable rate control
    WifiMacHelper wifiMac;
    wifi.SetRemoteStationManager ("ns3::ConstantRateWifiManager",
                                  "DataMode",StringValue ("DsssRate11Mbps"),
                                  "ControlMode",StringValue ("DsssRate11Mbps"));
    double txp=5;

    wifiPhy.Set ("TxPowerStart",DoubleValue (txp));
    wifiPhy.Set ("TxPowerEnd", DoubleValue (txp));

    wifiMac.SetType ("ns3::AdhocWifiMac");
//  PointToPointHelper pointToPoint;
//  pointToPoint.SetDeviceAttribute ("DataRate", StringValue ("5Mbps"));
//  pointToPoint.SetChannelAttribute ("Delay", StringValue ("2ms"));

  NetDeviceContainer devices;

  devices = wifi.Install (wifiPhy, wifiMac, nodes);
//		  pointToPoint.Install (nodes);

//  Ptr<RateErrorModel> em = CreateObject<RateErrorModel> ();
//  em->SetAttribute ("ErrorRate", DoubleValue (0.00001));
//  devices.Get (1)->SetAttribute ("ReceiveErrorModel", PointerValue (em));

  	MobilityHelper manet_mobility;
  	int64_t stream_index=0;

  	ObjectFactory pos;
  	pos.SetTypeId("ns3::RandomRectanglePositionAllocator");
  	pos.Set("X",StringValue("ns3::UniformRandomVariable[Min=0.0|Max=900]"));
  	pos.Set("Y",StringValue("ns3::UniformRandomVariable[Min=0.0|Max=900]"));

  	Ptr<PositionAllocator> taPositionAlloc = pos.Create ()->GetObject<PositionAllocator> ();
  	stream_index += taPositionAlloc->AssignStreams (stream_index);

  	std::stringstream ssSpeed;
  	ssSpeed << "ns3::UniformRandomVariable[Min=0.0|Max=" << 20 << "]";
  	std::stringstream ssPause;
  	ssPause << "ns3::ConstantRandomVariable[Constant=" << 0 << "]";
  	manet_mobility.SetMobilityModel ("ns3::RandomWaypointMobilityModel",
  	                                  "Speed", StringValue (ssSpeed.str ()),
  	                                  "Pause", StringValue (ssPause.str ()),
  	                                  "PositionAllocator", PointerValue (taPositionAlloc));

  	manet_mobility.SetPositionAllocator(taPositionAlloc);
  	manet_mobility.Install(nodes);
  	stream_index+= manet_mobility.AssignStreams(nodes,stream_index);

  	// Internet stack, IPv4 address, interfaces

  	AodvHelper aodv_routing;
  	Ipv4ListRoutingHelper list;
  	InternetStackHelper internet_stack;

  	list.Add(aodv_routing,50);
  	internet_stack.SetRoutingHelper(list);
  	internet_stack.Install(nodes);


  Ipv4AddressHelper address;
  address.SetBase ("10.1.1.0", "255.255.255.0");
  Ipv4InterfaceContainer interfaces = address.Assign (devices);

  uint16_t sinkPort = 8080;
  Address sinkAddress (InetSocketAddress (interfaces.GetAddress (0), sinkPort));
  PacketSinkHelper packetSinkHelper ("ns3::TcpSocketFactory", InetSocketAddress (Ipv4Address::GetAny (), sinkPort));
  ApplicationContainer sinkApps = packetSinkHelper.Install (nodes.Get (0));
  sinkApps.Start (Seconds (0.));
  sinkApps.Stop (Seconds (30.));

  Ptr<Socket> ns3TcpSocket = Socket::CreateSocket (nodes.Get (2), TcpSocketFactory::GetTypeId ());
//  ns3TcpSocket->TraceConnectWithoutContext ("CongestionWindow", MakeCallback (&CwndChange));

  Ptr<Ipv4L3Protocol> ipv4L3protocol = nodes.Get(0)->GetObject<Ipv4L3Protocol>();
  std::ostringstream oss;
    oss << "/NodeList/*/$ns3::Ipv4L3Protocol/LocalDeliver";
    ipv4L3protocol->TraceConnectWithoutContext("Tx",MakeCallback (&TransmitTrace));
//    ipv4L3protocol->TraceConnectWithoutContext("LocalDeliver",MakeCallback (&LocalDelivery));

    AsciiTraceHelper ascii;
    Ptr<OutputStreamWrapper> stream_broadcast = ascii.CreateFileStream ("fifth_broadcast.txt");
    Ptr<OutputStreamWrapper> stream_unicast = ascii.CreateFileStream ("fifth_unicast.txt");
    Config::Connect(oss.str (), MakeBoundCallback (&LocalDelivery,stream_broadcast,stream_unicast));

  Ptr<MyApp> app = CreateObject<MyApp> ();
  app->Setup (ns3TcpSocket, sinkAddress, 1040, 1000, DataRate ("1Mbps"));
  nodes.Get (3)->AddApplication (app);
  app->SetStartTime (Seconds (0.));
  app->SetStopTime (Seconds (30.));

  devices.Get (0)->TraceConnectWithoutContext ("PhyRxDrop", MakeCallback (&RxDrop));

  wifiPhy.EnablePcapAll (std::string ("fifth_manet"));

  Simulator::Stop (Seconds (30));
  Simulator::Run ();
  Simulator::Destroy ();

  return 0;
}

