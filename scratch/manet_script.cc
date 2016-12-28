/*
 * manet_script.cc
 *
 *  Created on: 20-Sep-2016
 *      Author: mishfad
 */

#include <fstream>
#include <iostream>
#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/mobility-module.h"
#include "ns3/wifi-module.h"
#include "ns3/aodv-module.h"
#include "ns3/olsr-module.h"
#include "ns3/dsdv-module.h"
#include "ns3/dsr-module.h"
#include "ns3/applications-module.h"
#include "ns3/netanim-module.h"
#include "src/wifi/model/wifi-remote-station-manager.h"
#include "src/core/model/vector.h"
#include "src/core/model/log-macros-enabled.h"
#include "src/applications/model/packet-sink.h"

using namespace ns3;
using namespace dsr;

NS_LOG_COMPONENT_DEFINE ("manet-tcp-experiment");

#define TE_RP_OLSR  1
#define TE_RP_AODV  2
#define TE_RP_DSDV  3
#define TE_RP_DSR   4




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
      buf[i] = i;
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
//      NS_LOG_UNCOND("Current total rx "<< m_totalRx);

      m_totalRx += packet->GetSize ();
      if (InetSocketAddress::IsMatchingType (from))
        {
    	  uint8_t *buf = new uint8_t [3];
    	  packet->CopyData(buf,3);
          NS_LOG_UNCOND ( Simulator::Now ().GetSeconds ()
                       << "s packet sink received "
                       <<  packet->GetSize () << " bytes from "
                       << InetSocketAddress::ConvertFrom(from).GetIpv4 ()
                       << " port " << InetSocketAddress::ConvertFrom (from).GetPort ()
                       << " total Rx " << m_totalRx << " bytes Packet ID:"<<packet->GetUid());
// my edits
          NS_LOG_LOGIC(" Data: "<<int(buf[0])<<" "<<int(buf[1]));

          SocketAddressTag tag;
          bool found=packet->PeekPacketTag (tag);
          if(found){}
          InetSocketAddress addr = InetSocketAddress::ConvertFrom (tag.GetAddress ());

          AsciiTraceHelper ascii;
          Ptr<OutputStreamWrapper> stream_rx = ascii.CreateFileStream("first_routing.txt",std::ios::app);
          if(socket->GetNode()->GetId()==1)
              *stream_rx->GetStream()<< Simulator::Now ().GetSeconds ()<<",Route:0"<<", Node:"<<socket->GetNode()->GetId()<<",Destination:10.1.1.2" << ",Source:" << addr.GetIpv4 () << ",packet:" << packet->GetUid ()<<std::endl;

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

class TcpExperiment
{
public:
  TcpExperiment ();
  void Run (double txp, std::string CSVfileName);
  std::string CommandSetup (int argc, char **argv);

private:
  void CheckThroughput ();
  void ReceivePacket (Ptr<Socket> socket);
  void MoveNode(Ptr<Node> node, Vector direction);
  void SetPosition (Ptr<Node> node, Vector position);
  Vector GetPosition (Ptr<Node> node);

  uint32_t port;
  uint32_t bytesTotal;
  uint32_t packetsReceived;

  std::string m_CSVfileName;
  std::string m_protocolName;
  double m_txp;
  bool m_traceMobility;
  uint32_t m_protocol;

};

TcpExperiment::TcpExperiment ()
  : port (9),
    bytesTotal (0),
    packetsReceived (0),
    m_CSVfileName ("manet-tcp.output.csv"),
    m_traceMobility (false),
    m_protocol (TE_RP_AODV)
{
}

static inline std::string PrintReceivedPacket (Ptr<Socket> socket, Ptr<Packet> packet)
{
  SocketAddressTag tag;
  bool found;
  found = packet->PeekPacketTag (tag);
  std::ostringstream oss;

  oss << Simulator::Now ().GetSeconds () << " " << socket->GetNode ()->GetId ();

  if (found)
    {
      InetSocketAddress addr = InetSocketAddress::ConvertFrom (tag.GetAddress ());
      oss << " received one packet from " << addr.GetIpv4 ();
    }
  else
    {
      oss << " received one packet!";
    }
  return oss.str ();
}

void TcpExperiment::ReceivePacket (Ptr<Socket> socket)
{
  Ptr<Packet> packet;
//  while ((packet = socket->Recv ()))
    {
      bytesTotal += packet->GetSize ();
      packetsReceived += 1;
      NS_LOG_UNCOND (PrintReceivedPacket (socket, packet));
      NS_LOG_UNCOND("PACKET RECEIVED");
    }
}

void TcpExperiment::CheckThroughput ()
{
  double kbs = (bytesTotal * 8.0) / 1000;
  bytesTotal = 0;

  std::ofstream out (m_CSVfileName.c_str (), std::ios::app);

  out << (Simulator::Now ()).GetSeconds () << ","
      << kbs << ","
      << packetsReceived << ","
      //<< m_nSinks << ","
      << m_protocolName << ","
      << m_txp << ""
      << std::endl;

  out.close ();
  packetsReceived = 0;
  Simulator::Schedule (Seconds (1.0), &TcpExperiment::CheckThroughput, this);
}

void TcpExperiment::SetPosition (Ptr<Node> node, Vector position)
{
  Ptr<MobilityModel> mobility = node->GetObject<MobilityModel> ();
  mobility->SetPosition (position);
}

Vector TcpExperiment::GetPosition (Ptr<Node> node)
{
  Ptr<MobilityModel> mobility = node->GetObject<MobilityModel> ();
  return mobility->GetPosition ();
}

void TcpExperiment::MoveNode(Ptr<Node> node, Vector direction)
{
    Vector pos = GetPosition (node);
    pos.x += direction.x;
    pos.y += direction.y;

    SetPosition (node, pos);
    Simulator::Schedule (Seconds (1.0), &TcpExperiment::MoveNode, this, node, direction);
}

std::string TcpExperiment::CommandSetup (int argc, char **argv)
{
  CommandLine cmd;
  cmd.AddValue ("CSVfileName", "The name of the CSV output file name", m_CSVfileName);
  cmd.AddValue ("traceMobility", "Enable mobility tracing", m_traceMobility);
  cmd.AddValue ("protocol", "1=OLSR;2=AODV;3=DSDV;4=DSR", m_protocol);
  cmd.Parse (argc, argv);
  return m_CSVfileName;
}


static void LocalDelivery(Ptr<OutputStreamWrapper> broadcast_stream,Ptr<OutputStreamWrapper> unicast_stream,std::string context,Ptr<const Node> node,const Ipv4Header &header, Ptr<const Packet> packet, uint32_t num)
{
	uint8_t buffer;

//	Ipv4Address addr("10.1.1.1");
//	TypeId tid = TypeId::LookupByName (socketid);
//	Ptr<Socket> sink = Socket::CreateSocket (node, tid);


	packet->CopyData(&buffer,1);
	if(header.GetDestination()=="10.1.1.255")
	{
//		*broadcast_stream->GetStream()<<Simulator::Now ().GetSeconds ()<<","<<context<<",Source. "<<header.GetSource() <<",Destination. "<<header.GetDestination()<<"\n";
		NS_LOG_UNCOND(Simulator::Now ().GetSeconds ()<<"\t"<<context<<"\tSource: "<<header.GetSource() <<"\tDestination: "<<header.GetDestination() <<"\tPacket:"<<int(buffer));

	}
//	else (header.GetDestination()=="10.1.1.1"||header.GetDestination()=="10.1.1.12")
	else
	{
		NS_LOG_UNCOND(Simulator::Now().GetSeconds()<<"Node: "<<node->GetId()<<" Local delivery: Packet received to "<<" Dest"<<header.GetDestination()<<" Source"<<header.GetSource());
//		*unicast_stream->GetStream()<<Simulator::Now ().GetSeconds ()<<","<<context<<",Source. "<<header.GetSource() <<",Destination. "<<header.GetDestination()<<"\n";
//		NS_LOG_UNCOND(Simulator::Now ().GetSeconds ()<<"\t"<<context<<"\tSource: "<<header.GetSource() <<"\tDestination: "<<header.GetDestination()<<"\tPacket:"<<int(buffer));
	}
}

static void
TransmitTrace(std::string context, Ptr<const Packet> packet, Ptr<Ipv4> ipv4,  uint32_t num)
{
	uint8_t *buffer = new uint8_t [5];
  packet->CopyData(buffer,1);
  NS_LOG_LOGIC (Simulator::Now ().GetSeconds () <<"\tContext:"<<context<< "\t Transmit trace\t" << packet->GetUid() <<"\t"<<ipv4->GetInstanceTypeId()<<"\t"<<int(*buffer));
}

static void TcpTransmit(Ptr<const Packet> p, const TcpHeader& header, Ptr<const TcpSocketBase> tcpsocketbase)
 {
	NS_LOG_UNCOND(Simulator::Now().GetSeconds()<<"packet:"<<p->GetUid()<<"Ack:"<<header.GetAckNumber());
 }

static void CwndChange (std::ofstream *cwndOut, uint32_t oldCwnd, uint32_t newCwnd)
{
  //NS_LOG_UNCOND (Simulator::Now ().GetSeconds () << "\t" << newCwnd);
    *cwndOut << Simulator::Now ().GetSeconds () << "\t" << newCwnd << std::endl;
}

static void RTTChange (std::ofstream *rttOut, Time old_time, Time new_time)
{
    *rttOut << Simulator::Now().GetSeconds() << "\t" << new_time.GetMilliSeconds() << std::endl;
}

static void RTOChange (std::ofstream *rtoOut, Time old_time, Time new_time)
{
    *rtoOut << Simulator::Now().GetSeconds() << "\t" << new_time.GetMilliSeconds() << std::endl;
}

void TcpExperiment::Run (double txp, std::string CSVfileName)
{
  Packet::EnablePrinting ();
  m_txp = txp;
  m_CSVfileName = CSVfileName;

  int nWifis = 20;

  double TotalTime = 60.0;
  std::string phyMode ("DsssRate1Mbps");
  //int nodeSpeed = 1; //in m/s
  //int nodePause = 0; //in s
  m_protocolName = "protocol";

	int64_t stream_index=0;

//	server nWifis-1, client 0
	std::string manet_destn="10.1.1.15";
	//Ipv4Address manet_destn("10.1.1.1");
	uint32_t manet_sourceId=0;
	uint32_t manet_DestnId=nWifis-2;
	//	int nNodes=2;
	int nSpeed=20; // in m/s
	int xRange=1500;
	int yRange=1500;
	//	double txp=1;
	Time start_time=Seconds (0);
	Time stop_time=Seconds (50);
	Time app_start=Seconds (0);
	Time app_stop=Seconds (90);


  //Set Non-unicastMode rate to unicast mode
  Config::SetDefault ("ns3::WifiRemoteStationManager::NonUnicastMode",StringValue (phyMode));

  NodeContainer adhocNodes;
  adhocNodes.Create (nWifis);

  // setting up wifi phy and channel using helpers
  WifiHelper wifi;
  wifi.SetStandard (WIFI_PHY_STANDARD_80211b);


  YansWifiPhyHelper wifiPhy =  YansWifiPhyHelper::Default ();
  YansWifiChannelHelper wifiChannel;
  wifiChannel.SetPropagationDelay ("ns3::ConstantSpeedPropagationDelayModel");
  wifiChannel.AddPropagationLoss ("ns3::FriisPropagationLossModel");
  wifiPhy.SetChannel (wifiChannel.Create ());

  // Add a non-QoS upper mac, and disable rate control
  NqosWifiMacHelper wifiMac = NqosWifiMacHelper::Default ();
  wifi.SetRemoteStationManager ("ns3::ConstantRateWifiManager",
                                "DataMode",StringValue (phyMode),
                                "ControlMode",StringValue (phyMode));

  wifiPhy.Set ("TxPowerStart",DoubleValue (txp));
  wifiPhy.Set ("TxPowerEnd", DoubleValue (txp));

  wifiMac.SetType ("ns3::AdhocWifiMac");
  NetDeviceContainer adhocDevices = wifi.Install (wifiPhy, wifiMac, adhocNodes);

  MobilityHelper mobilityAdhocStatic;
  //MobilityHelper mobilityAdhocMobile;
// my edit
	ObjectFactory pos;

	pos.SetTypeId("ns3::RandomRectanglePositionAllocator");
	std::stringstream ssxrange;
	std::stringstream ssyrange;
	ssxrange << "ns3::UniformRandomVariable[Min=0.0|Max=" << xRange << "]";
	ssyrange << "ns3::UniformRandomVariable[Min=0.0|Max=" << yRange << "]";

  	pos.Set("X",StringValue(ssxrange.str()));
  	pos.Set("Y",StringValue(ssyrange.str()));
  	Ptr<PositionAllocator> taPositionAlloc = pos.Create ()->GetObject<PositionAllocator> ();
  	stream_index += taPositionAlloc->AssignStreams (stream_index);

  	std::stringstream ssSpeed;
  	ssSpeed << "ns3::UniformRandomVariable[Min=0.0|Max=" << nSpeed << "]";
  	std::stringstream ssPause;
  	ssPause << "ns3::ConstantRandomVariable[Constant=" << 0 << "]";
  	mobilityAdhocStatic.SetMobilityModel ("ns3::RandomWaypointMobilityModel",
  	                                  "Speed", StringValue (ssSpeed.str ()),
  	                                  "Pause", StringValue (ssPause.str ()),
  	                                  "PositionAllocator", PointerValue (taPositionAlloc));

  	mobilityAdhocStatic.SetPositionAllocator(taPositionAlloc);
  	mobilityAdhocStatic.Install(adhocNodes);
  	stream_index+= mobilityAdhocStatic.AssignStreams(adhocNodes,stream_index);


//  Ptr<ListPositionAllocator> positionAllocator = CreateObject<ListPositionAllocator> ();
//
//  for (int i = 0; i < nWifis; i++)
//  {
//      positionAllocator->Add(Vector (i * 200.0, i*100.0, 0.0));
//  }
//
//  mobilityAdhocStatic.SetPositionAllocator(positionAllocator);
//  mobilityAdhocStatic.SetMobilityModel("ns3::ConstantPositionMobilityModel");
//  mobilityAdhocStatic.Install (adhocNodes);

  AodvHelper aodv;
  OlsrHelper olsr;
  DsdvHelper dsdv;
  DsrHelper dsr;
  DsrMainHelper dsrMain;
  Ipv4ListRoutingHelper list;
  InternetStackHelper internet;

  switch (m_protocol)
    {
    case 1:
      list.Add (olsr, 100);
      m_protocolName = "OLSR";
      break;
    case 2:
      list.Add (aodv, 100);
      m_protocolName = "AODV";
      break;
    case 3:
      list.Add (dsdv, 100);
      m_protocolName = "DSDV";
      break;
    case 4:
      m_protocolName = "DSR";
      break;
    default:
      NS_FATAL_ERROR ("No such protocol:" << m_protocol);
    }

  if (m_protocol < 4)
    {
      internet.SetRoutingHelper (list);
      internet.Install (adhocNodes);
    }
  else if (m_protocol == 4)
    {
      internet.Install (adhocNodes);
      dsrMain.Install (dsr, adhocNodes);
    }

  NS_LOG_INFO ("assigning ip address");

  Ipv4AddressHelper addressAdhoc;
  addressAdhoc.SetBase ("10.1.1.0", "255.255.255.0");
  Ipv4InterfaceContainer adhocInterfaces;
  adhocInterfaces = addressAdhoc.Assign (adhocDevices);

  uint16_t sinkPort = 8080;
  /*Address sinkAddress (InetSocketAddress (adhocInterfaces.GetAddress (nWifis - 1), sinkPort));
  PacketSinkHelper packetSinkHelper ("ns3::TcpSocketFactory", InetSocketAddress (Ipv4Address::GetAny (), sinkPort));
  ApplicationContainer sinkApps = packetSinkHelper.Install (adhocNodes.Get (nWifis - 1));
  sinkApps.Start (Seconds (5.0));
  sinkApps.Stop (Seconds (90.0));*/

  Address serverAddress (InetSocketAddress (adhocInterfaces.GetAddress (manet_DestnId), sinkPort));
  Ptr<Socket> serverTcpSocket = Socket::CreateSocket (adhocNodes.Get (manet_DestnId), TcpSocketFactory::GetTypeId ());
  serverTcpSocket->SetRecvCallback (MakeCallback (&TcpExperiment::ReceivePacket, this));
  Ptr<TcpServer> serverApp = CreateObject<TcpServer> ();
  serverApp->Setup(serverTcpSocket, InetSocketAddress (Ipv4Address::GetAny(), sinkPort));
//  NS_LOG_UNCOND("any "<<Ipv4Address::GetAny());
  adhocNodes.Get (nWifis - 1)->AddApplication(serverApp);
  serverApp->SetStartTime (Seconds(5.0));
  serverApp->SetStopTime (Seconds(TotalTime - 1.0));

  Ptr<Socket> clientTcpSocket = Socket::CreateSocket (adhocNodes.Get (0), TcpSocketFactory::GetTypeId ());
  Ptr<TcpClient> clientApp = CreateObject<TcpClient> ();
  clientApp->Setup (clientTcpSocket, serverAddress, 64, 1000, DataRate ("3Mbps"));
  adhocNodes.Get (0)->AddApplication (clientApp);
  clientApp->SetStartTime (Seconds (20.0));
  clientApp->SetStopTime (Seconds (TotalTime - 5.0));

  std::ofstream cwndOut ("cwnd.dat");
  clientTcpSocket->TraceConnectWithoutContext ("CongestionWindow", MakeBoundCallback(&CwndChange, &cwndOut));

  std::ofstream rttOut ("rtt.dat");
  clientTcpSocket->TraceConnectWithoutContext ("RTT", MakeBoundCallback(&RTTChange, &rttOut));

  std::ofstream rtoOut ("rto.dat");
  clientTcpSocket->TraceConnectWithoutContext ("RTO", MakeBoundCallback(&RTOChange, &rtoOut));

  Ptr<Ipv4L3Protocol> ipv4L3protocol = adhocNodes.Get(0)->GetObject<Ipv4L3Protocol>();
//  ipv4L3protocol->TraceConnectWithoutContext("LocalDeliver",MakeCallback (&LocalDelivery));

  std::ostringstream oss;
  oss << "/NodeList/*/$ns3::Ipv4L3Protocol/LocalDelivery";
  std::ostringstream oss_tx;
  oss_tx << "/NodeList/*/$ns3::Ipv4L3Protocol/Tx";
  std::ostringstream oss_tcp_tx;
  oss_tcp_tx << "/NodeList/*/$ns3::TcpSocketBase/Tx";


  AsciiTraceHelper ascii;
  Ptr<OutputStreamWrapper> stream_broadcast = ascii.CreateFileStream ("fifth_broadcast.txt");
  Ptr<OutputStreamWrapper> stream_unicast = ascii.CreateFileStream ("fifth_unicast.txt");
  Config::Connect(oss.str (), MakeBoundCallback (&LocalDelivery,stream_broadcast,stream_unicast));
  Config::Connect(oss_tx.str (), MakeCallback (&TransmitTrace));
  Config::Connect(oss_tcp_tx.str (), MakeCallback (&TcpTransmit));

//  Ptr<Ipv4L3Protocol> ipv4L3protocol = adhocNodes.Get (0)->GetObject<Ipv4L3Protocol>();
//  ipv4L3protocol->TraceConnectWithoutContext("Tx",MakeCallback (&TransmitTrace));


  NS_LOG_INFO ("Run Simulation.");

  CheckThroughput ();

//  AsciiTraceHelper ascii;
  Ptr<OutputStreamWrapper> stream = ascii.CreateFileStream("first_routing.txt");
  Ptr<OutputStreamWrapper> stream_mob = ascii.CreateFileStream("fifth_mobility.txt");
  Ptr<OutputStreamWrapper> stream_dat = ascii.CreateFileStream("manet_config.txt");
  Ptr<OutputStreamWrapper> stream_routing = ascii.CreateFileStream("aodv_routing_table.txt");
  *stream_dat->GetStream()<<"NNodes:"<<nWifis<<"\nnSpeed:"<<nSpeed<<"\nXRange:"<<xRange<<"\nYRange:"<<yRange;
  *stream_dat->GetStream()<<"\nDestn ID:"<<manet_DestnId<<"\nSource Id:"<<manet_sourceId;

  aodv.PrintRoutingTableAllAt(Seconds(0),stream_routing);
  aodv.PrintRoutingTableAllEvery(Seconds(5),stream_routing);

  //Simulator::Schedule (Seconds (1.5), &TcpExperiment::MoveNode, this, adhocNodes.Get (1), Vector (0.0, 2.5, 0.0));

  Simulator::Stop (Seconds (TotalTime+25));

  AnimationInterface anim ("manet-tcp-anim.xml");
  anim.EnablePacketMetadata();
  anim.SetMaxPktsPerTraceFile(6000000);
  anim.SetMobilityPollInterval(MilliSeconds(250));

  Simulator::Run ();

  cwndOut.close();
  rttOut.close();
  rtoOut.close();
  Simulator::Destroy ();
}

int main (int argc, char *argv[])
{
  TcpExperiment experiment;
  std::string CSVfileName = experiment.CommandSetup (argc,argv);

  double txp = 7.0;

  experiment.Run (txp, CSVfileName);
}


