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
//#define CHECK_STARTED_INTIMEWINDOW {if (!m_started || !IsInTimeWindow ()) return;}

//bool
//IsInTimeWindow ()
//{
//  if ((Simulator::Now () >= m_startTime) &&
//      (Simulator::Now () <= m_stopTime))
//    return true;
//  else
//    return false;
//}

uint16_t packetsReceived=0;
uint16_t port = 8080;
std::string socketid="ns3::TcpSocketFactory";

std::string manet_destn="10.1.1.1";
//Ipv4Address manet_destn("10.1.1.1");
uint32_t manet_sourceId=11;
uint32_t manet_DestnId=0;
int nNodes=2;
int nSpeed=20; // in m/s
int xRange=1000;
int yRange=1000;
double txp=1;
Time start_time=Seconds (0);
Time stop_time=Seconds (50);
Time app_start=Seconds (0);
Time app_stop=Seconds (90);
double TotalTime = 100.0;

//##################################################################


class TcpClient : public Application
{
public:

  TcpClient ();
  virtual ~TcpClient();

  void Setup (Ptr<Socket> socket, Address address, uint32_t packetSize, uint32_t nPackets, DataRate dataRate);

private:
  virtual void StartApplication (void);
  virtual void StopApplication (void);

  void ScheduleTx (void);
  void SendPacket (void);

  Ptr<Socket>     m_socket;
  Address         m_peer;	// server address
  uint32_t        m_packetSize;
  uint32_t        m_nPackets;
  DataRate        m_dataRate;
  EventId         m_sendEvent;
  bool            m_running;
  uint32_t        m_packetsSent;
};

TcpClient::TcpClient ()
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

TcpClient::~TcpClient()
{
  m_socket = 0;
}

void
TcpClient::Setup (Ptr<Socket> socket, Address address, uint32_t packetSize, uint32_t nPackets, DataRate dataRate)
{
  m_socket = socket;
  m_peer = address;
  m_packetSize = packetSize;
  m_nPackets = nPackets;
  m_dataRate = dataRate;
}

void
TcpClient::StartApplication (void)
{
  m_running = true;
  m_packetsSent = 0;
  m_socket->Bind ();
  m_socket->Connect (m_peer);
  SendPacket ();

}

void
TcpClient::StopApplication (void)
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
TcpClient::SendPacket (void)
{
  //Ptr<Packet> packet = Create<Packet> (m_packetSize);
  //m_socket->Send (packet);
  uint8_t *buf = new uint8_t [m_packetSize];
  for (uint32_t i = 0; i < m_packetSize; i++)
  {
      buf[i] = 7;
  }
  m_socket->Send(buf, m_packetSize, 0);
  delete buf;

  if (++m_packetsSent < m_nPackets)
    {
      ScheduleTx ();
    }
  else
  {
      if (m_socket)
      {
        //m_socket->Close ();
      }
      NS_LOG_UNCOND("Tcp client finished!");
  }
}

void
TcpClient::ScheduleTx (void)
{
  if (m_running)
    {
      Time tNext (Seconds (m_packetSize * 8 / static_cast<double> (m_dataRate.GetBitRate ())));
      m_sendEvent = Simulator::Schedule (tNext, &TcpClient::SendPacket, this);
    }
}

//-----------------------------------------------------------------------------

class TcpServer : public Application
{
public:

  TcpServer ();
  virtual ~TcpServer();

  void Setup (Ptr<Socket> socket, Address address);

protected:
  virtual void DoDispose (void);
private:
  virtual void StartApplication (void);
  virtual void StopApplication (void);
  void HandleAccept (Ptr<Socket> socket, const Address& from);
  void HandleRead (Ptr<Socket> socket);

  Ptr<Socket>     m_socket;;
  bool            m_running;
  uint32_t        m_packetsSent;
  Address         m_local;
  std::list<Ptr<Socket> > m_socketList;
  std::list<std::ofstream *> m_seqFileList;
  uint32_t        m_totalRx;
  TracedCallback<Ptr<const Packet>, const Address &> m_rxTrace;
};

TcpServer::TcpServer ()
  : m_socket (0),
    m_running (false),
    m_packetsSent (0),
    m_local ()
{
}

TcpServer::~TcpServer()
{
  m_socket = 0;
  m_totalRx = 0;
}

void TcpServer::DoDispose (void)
{
  NS_LOG_FUNCTION (this);
  m_socket = 0;
  m_socketList.clear ();

  // chain up
  Application::DoDispose ();
}

void
TcpServer::Setup (Ptr<Socket> socket, Address address)
{
  m_socket = socket;
  m_local = address;
}

void
TcpServer::StartApplication (void)
{
  m_running = true;
  m_socket->Bind (m_local);
  m_socket->Listen ();
  m_socket->SetAcceptCallback (MakeNullCallback<bool, Ptr<Socket>, const Address &> (), MakeCallback (&TcpServer::HandleAccept, this));
}

void
TcpServer::StopApplication (void)
{
  m_running = false;
  while(!m_socketList.empty ()) //these are accepted sockets, close them
  {
    Ptr<Socket> acceptedSocket = m_socketList.front ();
    m_socketList.pop_front ();
    acceptedSocket->Close ();
  }
  while(!m_seqFileList.empty ())
  {
      m_seqFileList.front()->close();
      m_seqFileList.pop_front();
  }
}

void TcpServer::HandleRead (Ptr<Socket> socket)
{
  NS_LOG_FUNCTION (this << socket);
  Ptr<Packet> packet;
  Address from;
  while ((packet = socket->RecvFrom (from)))
    {
      if (packet->GetSize () == 0)
        { //EOF
          break;
        }
      NS_LOG_UNCOND("Current total rx "<< m_totalRx);

      m_totalRx += packet->GetSize ();
      if (InetSocketAddress::IsMatchingType (from))
        {
          NS_LOG_UNCOND ("At time " << Simulator::Now ().GetSeconds ()
                       << "s packet sink received "
                       <<  packet->GetSize () << " bytes from "
                       << InetSocketAddress::ConvertFrom(from).GetIpv4 ()
                       << " port " << InetSocketAddress::ConvertFrom (from).GetPort ()
                       << " total Rx " << m_totalRx << " bytes "<<packet->GetUid());
        }
      else if (Inet6SocketAddress::IsMatchingType (from))
        {
          NS_LOG_INFO ("At time " << Simulator::Now ().GetSeconds ()
                       << "s packet sink received "
                       <<  packet->GetSize () << " bytes from "
                       << Inet6SocketAddress::ConvertFrom(from).GetIpv6 ()
                       << " port " << Inet6SocketAddress::ConvertFrom (from).GetPort ()
                       << " total Rx " << m_totalRx << " bytes");
        }
      m_rxTrace (packet, from);
    }
}

static void HandleGetPacket(std::ofstream *seq, Ptr<const Packet> packet)
{
    TcpHeader header;
    packet->PeekHeader(header);
    *seq << Simulator::Now().GetSeconds() << "\t" << header.GetSequenceNumber().GetValue() << std::endl;
}

void TcpServer::HandleAccept(Ptr<Socket> socket, const Address& from)
{
  NS_LOG_FUNCTION (this << socket << from);
  socket->SetRecvCallback (MakeCallback (&TcpServer::HandleRead, this));
  std::ostringstream sourceName;
  sourceName << "seq_" << m_seqFileList.size() << ".dat";
  static std::ofstream seqFile (sourceName.str().data());
  socket->TraceConnectWithoutContext("RxPacket", MakeBoundCallback(&HandleGetPacket, &seqFile));
  m_seqFileList.push_back(&seqFile);
  m_socketList.push_back (socket);

}



//##################################################################



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
    Address serverAddress (InetSocketAddress (interfaces.GetAddress (manet_sourceId), port));
    Ptr<Socket> serverTcpSocket = Socket::CreateSocket (nodes.Get (manet_sourceId), TcpSocketFactory::GetTypeId ());
    serverTcpSocket->SetRecvCallback (MakeCallback (&ReceivePacket));
    Ptr<TcpServer> serverApp = CreateObject<TcpServer> ();
    serverApp->Setup(serverTcpSocket, InetSocketAddress (Ipv4Address::GetAny(), port));
  //  NS_LOG_UNCOND("any "<<Ipv4Address::GetAny());
    nodes.Get (nNodes - 1)->AddApplication(serverApp);
    serverApp->SetStartTime (Seconds(1.0));
    serverApp->SetStopTime (stop_time);

    Ptr<Socket> clientTcpSocket = Socket::CreateSocket (nodes.Get (0), TcpSocketFactory::GetTypeId ());
    Ptr<TcpClient> clientApp = CreateObject<TcpClient> ();
    clientApp->Setup (clientTcpSocket, serverAddress, 1024, 1000, DataRate ("3Mbps"));
    nodes.Get (0)->AddApplication (clientApp);
    clientApp->SetStartTime (Seconds (5.0));
    clientApp->SetStopTime (Seconds (TotalTime - 5.0));


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
    *stream_dat->GetStream()<<"\nDestn ID:"<<manet_DestnId<<"\nSource Id:"<<manet_sourceId;

    aodv_routing.PrintRoutingTableAllAt(Seconds(0),stream_routing);
    aodv_routing.PrintRoutingTableAllEvery(Seconds(5),stream_routing);
//    MobilityAutoCheck ();
//    Simulator::Schedule (Seconds (2), &MobilityAutoCheck);
    AnimationInterface anim("fifth_manet.xml");

    Simulator::Stop (stop_time);
    Simulator::Run ();
    Simulator::Destroy ();

  return 0;
}

