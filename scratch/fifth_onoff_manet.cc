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
#include "ns3/netanim-module.h"

#include <cstdio>
#include <unistd.h>
#include <sstream>
#include <fstream>
#include <string>
#include <iomanip>
#include <map>


using namespace ns3;


NS_LOG_COMPONENT_DEFINE ("FifthScriptExample");

// ===========================================================================

uint16_t packetsReceived=0;
uint16_t port = 8080;
std::string socketid="ns3::UdpSocketFactory";

std::string manet_destn="10.1.1.1";
//Ipv4Address manet_destn("10.1.1.1");
uint32_t manet_sourceId=11;
uint32_t manet_DestnId=0;
int nNodes=20;
int nPackets=100;
int nSpeed=1; // in m/s
int xRange=1000;
int yRange=1000;
double txp=1;
Time start_time=Seconds (0);
Time stop_time=Seconds (50);
Time app_start=Seconds (0);
Time app_stop=Seconds (90);

//##################################################################
//##################################################################

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
  uint8_t 		  m_buffer[2];

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
  uint8_t *p=&m_buffer[0];
  Ptr<Packet> packet = Create<Packet> (p,m_packetSize);
  m_socket->Send (packet);
//  NS_LOG_UNCOND(Simulator::Now().GetSeconds()<<"\tPacket number: "<<int(*(p+1))<<int(*(p))<<"\tId: "<<packet->GetUid());
  if (m_buffer[1]>99)
     {
  	  m_buffer[1]=0;
     }

  if (m_buffer[0]==99)
   {
	  m_buffer[0]=0;
	  m_buffer[1]++;
   }
  else
   {
	  m_buffer[0]++;
   }

//  if (++m_packetsSent < m_nPackets)
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

void
PrintReceivedPacket (Ptr<Socket> socket, Ptr<Packet> packet)
{
  SocketAddressTag tag;
  bool found;
  found = packet->PeekPacketTag (tag);
  std::ostringstream oss;
  AsciiTraceHelper ascii;
  Ptr<OutputStreamWrapper> stream_rx = ascii.CreateFileStream("first_routing.txt",std::ios::app);

  oss << Simulator::Now ().GetSeconds () << " " << socket->GetNode()->GetId ();

  uint8_t buff[2];
  packet->CopyData(&buff[0],2);
//  oss<<"Inside printrxddata";
  if (found)
    {
      InetSocketAddress addr = InetSocketAddress::ConvertFrom (tag.GetAddress ());
      oss << " received one packet from " << addr.GetIpv4 ()<<"\tPacket: "<<packet->GetUid()<<" data:"<<int(buff[1])<<int(buff[0])<<packet->ToString();
      if(socket->GetNode()->GetId()==0)
    	  *stream_rx->GetStream()<< Simulator::Now ().GetSeconds ()<<",Route:0"<<", Node:"<<socket->GetNode()->GetId()<<",Destination:10.1.1.1" << ",Source:" << addr.GetIpv4 () << ",packet:" << packet->GetUid ()<<std::endl;
//      NS_LOG_UNCOND(Simulator::Now ().GetSeconds ()<<",Route:0"<<", Node:"<<socket->GetNode()->GetId()<<",Destination:10.1.1.1"  << ",Source:" << addr.GetIpv4 () << ",packet:" << packet->GetUid ());
    }
  else
    {
      oss << " \treceived one packet!"<<"\tPacket: "<<packet->GetUid()<<" data:"<<int(buff[1])<<int(buff[0]);
    }
  NS_LOG_UNCOND(oss.str ());
}

void
ReceivePacket (Ptr<Socket> socket)
{
  Ptr<Packet> packet;
  while ((packet = socket->Recv ()))
    {
      packetsReceived += 1;
      NS_LOG_LOGIC("Receiving data"<<packetsReceived);
      PrintReceivedPacket (socket, packet);
    }
}

void
SetupPacketReceive (Ipv4Address addr, Ptr<Node> node)
{
  TypeId tid = TypeId::LookupByName (socketid);
  Ptr<Socket> sink = Socket::CreateSocket (node, tid);
//  NS_LOG_UNCOND("Node: "<<node->GetId()<<"\tConnection: "<<tid);
  InetSocketAddress local = InetSocketAddress (addr, port);
  sink->Bind (local);
  sink->SetRecvCallback (MakeCallback (&ReceivePacket));
}


//static void
//CwndChange (uint32_t oldCwnd, uint32_t newCwnd)
//{
////  NS_LOG_UNCOND (Simulator::Now ().GetSeconds () << "\t" << newCwnd);
//}

//static void
//TransmitTrace(Ptr<const Packet> packet, Ptr<Ipv4> ipv4,  uint32_t num)
//{
//  uint8_t buffer;
//  packet->CopyData(&buffer,1);
//  NS_LOG_LOGIC (Simulator::Now ().GetSeconds () << "\t Transmit trace\t" << packet->GetUid() <<"\t"<<ipv4->GetInstanceTypeId()<<"\t"<<int(buffer));
//}

static void
LocalDelivery(Ptr<OutputStreamWrapper> broadcast_stream,Ptr<OutputStreamWrapper> unicast_stream,std::string context,Ptr<const Node> node,const Ipv4Header &header, Ptr<const Packet> packet, uint32_t num)
{
	uint8_t buffer;

//	Ipv4Address addr("10.1.1.1");
//	TypeId tid = TypeId::LookupByName (socketid);
//	Ptr<Socket> sink = Socket::CreateSocket (node, tid);


	packet->CopyData(&buffer,1);
	if(header.GetDestination()=="10.1.1.255")
	{
//		*broadcast_stream->GetStream()<<Simulator::Now ().GetSeconds ()<<","<<context<<",Source. "<<header.GetSource() <<",Destination. "<<header.GetDestination()<<"\n";
//		NS_LOG_UNCOND(Simulator::Now ().GetSeconds ()<<"\t"<<context<<"\tSource: "<<header.GetSource() <<"\tDestination: "<<header.GetDestination() <<"\tPacket:"<<int(buffer));

	}
//	else (header.GetDestination()=="10.1.1.1"||header.GetDestination()=="10.1.1.12")
	else
	{
//		NS_LOG_UNCOND(Simulator::Now().GetSeconds()<<"Node: "<<node->GetId()<<" Local delivery: Packet received to "<<" Dest"<<header.GetDestination()<<" Source"<<header.GetSource());
		*unicast_stream->GetStream()<<Simulator::Now ().GetSeconds ()<<","<<context<<",Source. "<<header.GetSource() <<",Destination. "<<header.GetDestination()<<"\n";
//		NS_LOG_UNCOND(Simulator::Now ().GetSeconds ()<<"\t"<<context<<"\tSource: "<<header.GetSource() <<"\tDestination: "<<header.GetDestination()<<"\tPacket:"<<int(buffer));
	}
}


void
ipv4Output (Ptr< const Packet > packet, Ptr< Ipv4 > ipv4, uint32_t interface)
	{
		uint8_t buffer;
		packet->CopyData(&buffer,1);
		NS_LOG_LOGIC(Simulator::Now ().GetSeconds ()<<"\t packet is: "<<int(buffer));
	}

static void
RxDrop (Ptr<const Packet> p)
{
  NS_LOG_UNCOND ("RxDrop at " << Simulator::Now ().GetSeconds ());
}

int 
main (int argc, char *argv[])
{

  NodeContainer nodes;
  nodes.Create (nNodes);


  // setting up wifi phy and channel using helpers
    WifiHelper wifi;
    wifi.SetStandard (WIFI_PHY_STANDARD_80211b);

    YansWifiPhyHelper wifiPhy =  YansWifiPhyHelper::Default ();
    YansWifiChannelHelper wifiChannel;
    wifiChannel.SetPropagationDelay ("ns3::ConstantSpeedPropagationDelayModel");
    wifiChannel.AddPropagationLoss ("ns3::FriisPropagationLossModel");
    wifiPhy.SetChannel (wifiChannel.Create ());

    // Add a mac and disable rate control
//    WifiMacHelper wifiMac;
    NqosWifiMacHelper wifiMac = NqosWifiMacHelper::Default ();
    wifi.SetRemoteStationManager ("ns3::ConstantRateWifiManager",
                                  "DataMode",StringValue ("DsssRate1Mbps"),
                                  "ControlMode",StringValue ("DsssRate1Mbps"));

    wifiPhy.Set ("TxPowerStart",DoubleValue (txp));
    wifiPhy.Set ("TxPowerEnd", DoubleValue (txp));

    wifiMac.SetType ("ns3::AdhocWifiMac");
//  PointToPointHelper pointToPoint;
//  pointToPoint.SetDeviceAttribute ("DataRate", StringValue ("5Mbps"));
//  pointToPoint.SetChannelAttribute ("Delay", StringValue ("2ms"));

  NetDeviceContainer devices = wifi.Install (wifiPhy, wifiMac, nodes);
//		  pointToPoint.Install (nodes);

//  Ptr<RateErrorModel> em = CreateObject<RateErrorModel> ();
//  em->SetAttribute ("ErrorRate", DoubleValue (0.00001));
//  devices.Get (1)->SetAttribute ("ReceiveErrorModel", PointerValue (em));

  	MobilityHelper manet_mobility;
  	int64_t stream_index=0;

  	ObjectFactory pos;
  	pos.SetTypeId("ns3::RandomRectanglePositionAllocator");
  	std::stringstream ssxrange;
  	std::stringstream ssyrange;
 	ssxrange << "ns3::UniformRandomVariable[Min=0.0|Max=" << xRange << "]";
 	ssyrange << "ns3::UniformRandomVariable[Min=0.0|Max=" << yRange << "]";

//  	pos.Set("X",StringValue("ns3::UniformRandomVariable[Min=0.0|Max=1000]"));
//  	pos.Set("Y",StringValue("ns3::UniformRandomVariable[Min=0.0|Max=1000]"));
  	pos.Set("X",StringValue(ssxrange.str()));
  	pos.Set("Y",StringValue(ssyrange.str()));

  	Ptr<PositionAllocator> taPositionAlloc = pos.Create ()->GetObject<PositionAllocator> ();
  	stream_index += taPositionAlloc->AssignStreams (stream_index);

  	std::stringstream ssSpeed;
  	ssSpeed << "ns3::UniformRandomVariable[Min=0.0|Max=" << nSpeed << "]";
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

//  ns3TcpSocket->TraceConnectWithoutContext ("CongestionWindow", MakeCallback (&CwndChange));

  Ptr<Ipv4L3Protocol> ipv4L3protocol = nodes.Get(0)->GetObject<Ipv4L3Protocol>();
  Ptr<Ipv4PacketProbe> ipv4packetprob= nodes.Get(0)->GetObject<Ipv4PacketProbe>();

    std::ostringstream oss;
    oss << "/NodeList/*/$ns3::Ipv4L3Protocol/LocalDeliveryWithNode";
//    ipv4L3protocol->TraceConnectWithoutContext("Tx",MakeCallback (&TransmitTrace));
//    ipv4packetprob->TraceConnectWithoutContext("Output",MakeCallback(&ipv4Output));
//    ipv4L3protocol->TraceConnectWithoutContext("LocalDeliver",MakeCallback (&LocalDelivery));

    AsciiTraceHelper ascii;
    Ptr<OutputStreamWrapper> stream_broadcast = ascii.CreateFileStream ("fifth_broadcast.txt");
    Ptr<OutputStreamWrapper> stream_unicast = ascii.CreateFileStream ("fifth_unicast.txt");
    Config::Connect(oss.str (), MakeBoundCallback (&LocalDelivery,stream_broadcast,stream_unicast));

// Setting up the application
    OnOffHelper onoff1 (socketid,InetSocketAddress (Ipv4Address::GetAny(), port));
    onoff1.SetAttribute ("OnTime", StringValue ("ns3::ConstantRandomVariable[Constant=2.0]"));
    onoff1.SetAttribute ("OffTime", StringValue ("ns3::ConstantRandomVariable[Constant=3.0]"));
    AddressValue remoteAddress (InetSocketAddress (interfaces.GetAddress (manet_DestnId), port));
    onoff1.SetAttribute ("Remote", remoteAddress);
    ApplicationContainer myapp = onoff1.Install (nodes.Get(manet_sourceId));

//    uint16_t sinkPort = 9;
//    Address sinkAddress (InetSocketAddress (interfaces.GetAddress (manet_DestnId), port));
//
//    TypeId tid1 = TypeId::LookupByName (socketid);
//    Ptr<Socket> ns3Socket = Socket::CreateSocket (nodes.Get (manet_sourceId), tid1);
//    Ptr<MyApp> app = CreateObject<MyApp> ();
//    app->Setup (ns3Socket, sinkAddress, 1040, 1000, DataRate ("1000Kbps"));
//    nodes.Get (13)->AddApplication (app);
//    app->SetStartTime (Seconds (5.));
//    app->SetStopTime (Seconds (30.));

//	Ipv4Address addr("10.1.1.1");
    PacketSinkHelper packetSinkHelper (socketid, InetSocketAddress (interfaces.GetAddress (manet_DestnId), port));
    ApplicationContainer sinkApps = packetSinkHelper.Install (nodes.Get (manet_DestnId));


//    for (int i=0;i<nNodes;i++)
    int i=0;
    	SetupPacketReceive (interfaces.GetAddress (manet_DestnId), nodes.Get (i));
//    Ptr<Socket> sink1 = SetupPacketReceive (interfaces.GetAddress (1), nodes.Get (1));



    devices.Get (0)->TraceConnectWithoutContext ("PhyRxDrop", MakeCallback (&RxDrop));

//    std::string tr_name ("manet-routing-compare");
//    wifiPhy.EnablePcapAll (std::string ("fifth_manet"));
//    MobilityHelper::EnableAsciiAll (ascii.CreateFileStream (tr_name + ".mob"));

//    Ptr<OutputStreamWrapper> stream_rx = ascii.CreateFileStream("fifth_received.txt");
    Ptr<OutputStreamWrapper> stream = ascii.CreateFileStream("first_routing.txt");
    Ptr<OutputStreamWrapper> stream_mob = ascii.CreateFileStream("fifth_mobility.txt");
    Ptr<OutputStreamWrapper> stream_dat = ascii.CreateFileStream("manet_config.txt");
    Ptr<OutputStreamWrapper> stream_routing = ascii.CreateFileStream("aodv_routing_table.txt");
    *stream_dat->GetStream()<<"NNodes:"<<nNodes<<"\nnSpeed:"<<nSpeed<<"\nXRange:"<<xRange<<"\nYRange:"<<yRange;
    *stream_dat->GetStream()<<"\nDestn ID:"<<manet_DestnId<<"\nSource Id:"<<manet_sourceId<<"\nnPackets: "<<nPackets;

    aodv_routing.PrintRoutingTableAllAt(Seconds(0),stream_routing);
    aodv_routing.PrintRoutingTableAllEvery(Seconds(5),stream_routing);
//    MobilityAutoCheck ();
//    Simulator::Schedule (Seconds (2), &MobilityAutoCheck);
    AnimationInterface anim("fifth_manet.xml");
    myapp.Start (Seconds (0));
	myapp.Stop (stop_time);

    sinkApps.Start (app_start);
    sinkApps.Stop (app_stop);

    Simulator::Stop (stop_time);
    Simulator::Run ();
    Simulator::Destroy ();

  return 0;
}

