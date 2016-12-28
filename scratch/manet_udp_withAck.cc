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

#include "manet_udp_withAck.h"

using namespace ns3;

NS_LOG_COMPONENT_DEFINE ("manetudpwithack");

UdpAckHeader::UdpAckHeader ()
  : m_sequenceNumber (0),
    m_ackNumber (0)
{
}
UdpAckHeader::~UdpAckHeader ()
{
}

void
UdpAckHeader::SetSequenceNumber (SequenceNumber32 sequenceNumber)
{
  m_sequenceNumber = sequenceNumber;
}

void
UdpAckHeader::SetAckNumber (SequenceNumber32 ackNumber)
{
  m_ackNumber = ackNumber;
}

SequenceNumber32
UdpAckHeader::GetSequenceNumber () const
{
  return m_sequenceNumber;
}

SequenceNumber32
UdpAckHeader::GetAckNumber () const
{
  return m_ackNumber;
}

void
UdpAckHeader::SetDestinationPort (uint16_t port)
{
  m_destinationPort = port;
}
void
UdpAckHeader::SetSourcePort (uint16_t port)
{
  m_sourcePort = port;
}
uint16_t
UdpAckHeader::GetSourcePort (void) const
{
  return m_sourcePort;
}
uint16_t
UdpAckHeader::GetDestinationPort (void) const
{
  return m_destinationPort;
}
Address
UdpAckHeader::GetSourceAddress (void) const
{
  return m_source;
}

bool
UdpAckHeader::GetBroadcastFlag(void)
{
	return m_broadcastFlag;
}

void
UdpAckHeader::SetBroadcastFlag(bool val)
{
	m_broadcastFlag=val;
}


void
UdpAckHeader::InitializeChecksum (Address source,
                               Address destination)
{
  m_source = source;
  m_destination = destination;
}



TypeId
UdpAckHeader::GetInstanceTypeId (void) const
{
  return GetTypeId ();
}

void
UdpAckHeader::Print (std::ostream &os)  const
{

  os << " Seq=" << m_sequenceNumber << " Ack=" << m_ackNumber;

}

uint32_t
UdpAckHeader::GetSerializedSize (void)  const
{
  return 1000;
}

void
UdpAckHeader::Serialize (Buffer::Iterator start)  const
{
  Buffer::Iterator i = start;
  i.WriteHtonU32 (m_sequenceNumber.GetValue ());
  i.WriteHtonU32 (m_ackNumber.GetValue ());
  i.WriteHtonU16 (0);

  // Serialize options if they exist
  // This implementation does not presently try to align options on word
  // boundaries using NOP options
  uint32_t optionLen = 0;

  // padding to word alignment; add ENDs and/or pad values (they are the same)
  while (optionLen % 4)
    {
      i.WriteU8 (TcpOption::END);
      ++optionLen;
    }

}

uint32_t
UdpAckHeader::Deserialize (Buffer::Iterator start)
{
  Buffer::Iterator i = start;
  m_sequenceNumber = i.ReadNtohU32 ();
  m_ackNumber = i.ReadNtohU32 ();
  i.Next (2);
    {
      uint8_t kind = i.PeekU8 ();
      Ptr<TcpOption> op;
      uint32_t optionSize;
      if (TcpOption::IsKindKnown (kind))
        {
          op = TcpOption::CreateOption (kind);
        }
      else
        {
          op = TcpOption::CreateOption (TcpOption::UNKNOWN);
          NS_LOG_WARN ("Option kind " << static_cast<int> (kind) << " unknown, skipping.");
        }
      optionSize = op->Deserialize (i);
      if (optionSize != op->GetSerializedSize ())
        {
          NS_LOG_ERROR ("Option did not deserialize correctly");
        }
    }

  return GetSerializedSize ();
}



SendApp::SendApp ()
  : m_count(10),
	m_socket (0),
	m_peer (),
	m_local (),
	m_packetSize (0),
    m_nPackets (0),
    m_dataRate (0),
    m_sendEvent (),
    m_running (false),
    m_packetsSent (0),
	m_windowSize(536),
	m_nextTxSequence(1),
	m_highTxMark(0),
	m_rto(Seconds(1))
{
	m_txBuffer = CreateObject<TcpTxBuffer> ();
}

SendApp::~SendApp()
{
  m_socket = 0;
}

void
SendApp::Setup (Ptr<Socket> socket, Address sinkaddress, Address sourceaddress, uint32_t packetSize, uint32_t nPackets, DataRate dataRate)
{
  m_socket = socket;
  m_peer = sinkaddress;
  m_local= sourceaddress;
  m_packetSize = packetSize;
  m_nPackets = nPackets;
  m_dataRate = dataRate;
}

void
SendApp::StartApplication (void)
{
  m_running = true;
  m_packetsSent = 0;
  TypeId tid = TypeId::LookupByName (socketid);
  // Create the socket if not already
  if (!m_receivesocket)
	{
	  m_receivesocket = Socket::CreateSocket (GetNode (), tid);
	  m_socket->Bind ();
	  m_socket->Connect (m_peer);
	}
// setup receive callback for the sending socket
  m_socket->SetRecvCallback (MakeCallback (&SendApp::HandleRead, this));

  SendPacket ();
}

void
SendApp::StopApplication (void)
{
  m_running = false;

  if (m_sendEvent.IsRunning ())
    {
      Simulator::Cancel (m_sendEvent);
    }

  if (m_socket)
    {
      m_socket->Close ();
      m_socket->SetRecvCallback (MakeNullCallback<void, Ptr<Socket> > ());
      m_socket = 0;
    }
}

void
SendApp::Retransmit()
{
	// If all data are received (non-closing socket and nothing to send), just return
	if (m_txBuffer->HeadSequence () >= m_highTxMark)
	  {
		return;
	  }
	m_nextTxSequence = m_txBuffer->HeadSequence (); // Restart from highest Ack
	  // Retransmit a data packet: Call SendDataPacket
	uint32_t sz = SendDataPacket (m_txBuffer->HeadSequence (), m_packetSize);
	++m_retransOut;

	// In case of RTO, advance m_nextTxSequence
	m_nextTxSequence = std::max (m_nextTxSequence.Get (), m_txBuffer->HeadSequence () + sz);

	NS_LOG_DEBUG ("retxing seq " << m_txBuffer->HeadSequence ());


}

void
SendApp::ReTxTimeout ()
{
  NS_LOG_FUNCTION (this);
  NS_LOG_LOGIC (" ReTxTimeout Expired at time " << Simulator::Now ().GetSeconds ());
  // If erroneous timeout in closed/timed-wait state, just return
  // If all data are received (non-closing socket and nothing to send), just return
  if (m_txBuffer->HeadSequence () >= m_highTxMark)
	{
	  return;
	}

  m_recover = m_highTxMark;
  Retransmit ();

}

uint32_t
SendApp::SendDataPacket (SequenceNumber32 seq, uint32_t maxSize)
{
	bool isRetransmission = false;

	if (seq != m_highTxMark)
	{
	  isRetransmission = true;
	}

//	creates a new packet by reading maxSize number of bytes starting from seq
	Ptr<Packet> p = m_txBuffer->CopyFromSequence (maxSize, seq);
	uint32_t sz = p->GetSize (); // Size of packet

//	uint32_t remainingData = m_txBuffer->SizeFromSequence (seq + SequenceNumber32 (sz));
//	NS_LOG_UNCOND(remainingData);

	if (m_retxEvent.IsExpired ())
	{
//	Schedules retransmit timeout. (Standard techniques is, if this is a retransmission, double the timer).
//	Since we are not bothered about it, we keep it m_rto
	  if (isRetransmission)
		{ // This is a retransmit
		  // RFC 6298, clause 2.5
		  Time doubledRto = m_rto;
		  m_rto = Min (doubledRto, Time::FromDouble (60,  Time::S)); // upper thresholding by 60s
		}

	  NS_LOG_LOGIC (this << " SendDataPacket Schedule ReTxTimeout at time " <<
					Simulator::Now ().GetSeconds () << " to expire at time " <<
					(Simulator::Now () + m_rto.Get ()).GetSeconds () );
	  m_retxEvent = Simulator::Schedule (m_rto, &SendApp::ReTxTimeout, this);
	}

//	Adding header
	UdpAckHeader sendackheader;
	sendackheader.SetSequenceNumber(seq);

//	Ipv4Address ipv4address = Ipv4Address ("255.255.255.255");
//	Ptr<Ipv4> ipv4 = GetNode()->GetObject<Ipv4> ();
//
//	Ptr<aodv::RoutingTable> RT=GetNode()->GetObject<aodv::RoutingTable>();
//	std::map<Ipv4Address, aodv::RoutingTableEntry> table;
//	table=RT->GetRoutingTable();
////	aodv::RoutingTableEntry RT_entry;
////	RT.LookupRoute(Ipv4Address("10.1.1.13"),RT_entry);
//	NS_LOG_UNCOND(Simulator::Now().GetSeconds()<<"Node: "<<GetNode()->GetId()<<" Neighbors:");
////			<<RT_entry.IsPrecursorListEmpty());
//
//	for (std::map<Ipv4Address, aodv::RoutingTableEntry>::const_iterator i =
//	         table.begin (); i != table.end (); ++i)
//	    {
//		  Ptr<Ipv4Route> route=i->second.GetRoute();
//		  NS_LOG_UNCOND(Simulator::Now().GetSeconds()<<
//				  "Destination:"<< route->GetDestination ()
//				  << ",Gateway:" << route->GetGateway ()  );
//	    }


//	std::map<Ipv4Address, uint32_t> unreachable;
//	RT.GetListOfDestinationWithNextHop(Ipv4Address("10.1.1.13"),unreachable);
//
//	NS_LOG_UNCOND("Neighbors:");
//	for (std::map<Ipv4Address, uint32_t>::const_iterator i =
//	         unreachable.begin (); i != unreachable.end (); ++i)
//	    {
//		  NS_LOG_UNCOND("Address: "<<i->first);
//	    }

//	NS_LOG_UNCOND(unreachable);
//	if (ipv4 != 0)
//	    {
//		  	Ptr<Ipv4Route> route;
//		  	ipv4->GetRoutingProtocol()->GetObject<Ipv4RoutingTableEntry>();
//		  	Ipv4Address address("10.1.1.1");
//		  	route->SetDestination(address);
//		  	NS_LOG_UNCOND("Destn: "<< route->GetDestination());
//	    }


	NS_LOG_LOGIC("Sending seq num: "<<sendackheader.GetSequenceNumber());
	p->AddHeader(sendackheader);

	//	Send the data packet
	m_socket->Send (p);
	sendackheader.SetBroadcastFlag(true);
//	NS_LOG_UNCOND("broadcasting...");
//	m_socket->SendTo(p,0,InetSocketAddress (ipv4address, port));

//	UdpAckHeader sendackheader;
//	p->PeekHeader(sendackheader);
//	NS_LOG_UNCOND("Sending seq num: "<<sendackheader.GetSequenceNumber());

	if (seq + sz > m_highTxMark)
	    {
//	      Simulator::ScheduleNow (&TcpSocketBase::NotifyDataSent, this, (seq + sz - m_highTxMark.Get ()));
	    }
	  // Update highTxMark
	  m_highTxMark = std::max (seq + sz, m_highTxMark.Get ());
	  return sz;

}

void
SendApp::SendPendingPackets()
{
  uint32_t nPacketsSent = 0;
  while (m_txBuffer->SizeFromSequence (m_nextTxSequence))
	{
	  uint32_t w = m_windowSize; // Get available window size
//	Sends packet of size 'w' bytes from the transmit buffer, starting from m_nextTxSequence
	  uint32_t sz = SendDataPacket (m_nextTxSequence, w);
	  nPacketsSent++;                             // Count sent this loop
	  m_nextTxSequence += sz;                     // Advance next tx sequence
	}
  if (nPacketsSent > 0)
	{
	  NS_LOG_DEBUG ("SendPendingData sent " << nPacketsSent << " segments");
	}
}


void
SendApp::SendPacket (void)
{
//	First, we move all the packets to the transmit buffer.
//	Later, the packets will be send by reading from the buffer in SendPendingData
	  Ptr<Packet> packet = Create<Packet> (m_packetSize);
      if (!m_txBuffer->Add (packet))
        { // TxBuffer overflow, send failed
    	  assert("buffer full");
        }
      SendPendingPackets();
//	  m_socket->Send (packet);

//  if (++m_packetsSent < m_nPackets)
    {
//      ScheduleTx ();
    }
}

void
SendApp::ScheduleTx (void)
{
  if (m_running)
    {
      Time tNext (Seconds (m_packetSize * 8 / static_cast<double> (m_dataRate.GetBitRate ())));
      m_sendEvent = Simulator::Schedule (tNext, &SendApp::SendPacket, this);
    }
}


void SendApp::HandleRead (Ptr<Socket> socket)
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
//      m_totalRx += packet->GetSize ();
      UdpAckHeader ackheader;
      packet->PeekHeader(ackheader);
//      if (InetSocketAddress::IsMatchingType (from))
        {
//    	  	  NS_LOG_UNCOND ("At time " << Simulator::Now ().GetSeconds ()
//                       << "s Send App received "
//                       <<  packet->GetSize () << " bytes from "
//                       << InetSocketAddress::ConvertFrom(from).GetIpv4 ()
//                       << " port " << InetSocketAddress::ConvertFrom (from).GetPort ());
//					   <<"ack :"<<ackheader.GetAckNumber());
    	  	  AsciiTraceHelper ascii;
    	  	  Ptr<OutputStreamWrapper> stream_packToseq = ascii.CreateFileStream("packetidToSeq.txt",std::ios::app);
    	  	  *stream_packToseq->GetStream()<<"PacketId: "<<packet->GetUid()<<",SequenceNum:"<<ackheader.GetAckNumber()<<std::endl;

          	  m_txBuffer->SetHeadSequence (ackheader.GetAckNumber()+m_windowSize);
//          	  NS_LOG_UNCOND("New transmit headsequence: "<<m_txBuffer->HeadSequence ());
//          	  m_count++;
//              packet->RemoveAllPacketTags ();
//              packet->RemoveAllByteTags ();
//              if (m_count<2)
//              {
////          	  Ptr<Packet> newPacket = Create<Packet> ();
//				  UdpAckHeader newackheader;	//= Create <UdpAckHeader>();
//				  newackheader.InitializeChecksum(m_local,m_peer);
//				  SequenceNumber32 seq(124);
//				  newackheader.SetSequenceNumber(seq);
//				  NS_LOG_UNCOND("Sending next seq: "<<newackheader.GetAckNumber());
//				  packet->AddHeader(newackheader);
//
//				 socket->Send(packet);
//              }

//          sending back the acknowledgment for the received packet
//          m_peer=ackheader.GetSourceAddress();
//          Ptr<Packet> newPacket = Create<Packet> ();
//          UdpAckHeader newackheader;	//= Create <UdpAckHeader>();
//          newackheader.InitializeChecksum(m_local,m_peer);
//            SequenceNumber32 seq(123);
//          newackheader.SetAckNumber(ackheader.GetSequenceNumber());
//          NS_LOG_UNCOND("Sending acknowledgment for : "<<newackheader.GetAckNumber());
//		  newPacket->AddHeader(newackheader);
//
//		  Ptr<Socket> newSocket;
//		  newSocket->Bind ();
//		  newSocket->Connect (m_peer);
//		  newSocket->Send (newPacket);

//        }
//      else if (Inet6SocketAddress::IsMatchingType (from))
//        {
//          NS_LOG_INFO ("At time " << Simulator::Now ().GetSeconds ()
//                       << "s packet sink received "
//                       <<  packet->GetSize () << " bytes from "
//                       << Inet6SocketAddress::ConvertFrom(from).GetIpv6 ()
//                       << " port " << Inet6SocketAddress::ConvertFrom (from).GetPort ());
//                       << " total Rx " << m_totalRx << " bytes");
        }
//      m_rxTrace (packet, from);
    }
}


void SendApp::HandlePeerClose (Ptr<Socket> socket)
{
  NS_LOG_FUNCTION (this << socket);
}

void SendApp::HandlePeerError (Ptr<Socket> socket)
{
  NS_LOG_FUNCTION (this << socket);
}


void SendApp::HandleAccept (Ptr<Socket> s, const Address& from)
{
  NS_LOG_FUNCTION (this << s << from);
  s->SetRecvCallback (MakeCallback (&SendApp::HandleRead, this));
//  m_socketList.push_back (s);
}

//#################################################################################################################################
//#################################################################################################################################


ReceiverApp::ReceiverApp ()
{
  NS_LOG_FUNCTION (this);
  m_socket = 0;
  m_totalRx = 0;
}

ReceiverApp::~ReceiverApp()
{
  NS_LOG_FUNCTION (this);
}

void
ReceiverApp::Setup (TypeId tid,Address address)
{
  m_local = address;
  m_tid=tid;
//  m_sinknode=sinknode;
}

// Application Methods
void ReceiverApp::StartApplication ()    // Called at time specified by Start
{
  NS_LOG_FUNCTION (this);
  // Create the socket if not already
  if (!m_socket)
    {
      m_socket = Socket::CreateSocket (GetNode(), m_tid);
      NS_LOG_UNCOND("Created socket at "<<GetNode()->GetId());
      m_socket->Bind (m_local);
    }

  m_socket->SetRecvCallback (MakeCallback (&ReceiverApp::HandleRead, this));
  m_socket->SetCloseCallbacks (
    MakeCallback (&ReceiverApp::HandlePeerClose, this),
    MakeCallback (&ReceiverApp::HandlePeerError, this));
}

void ReceiverApp::StopApplication ()     // Called at time specified by Stop
{
  NS_LOG_FUNCTION (this);
  while(!m_socketList.empty ()) //these are accepted sockets, close them
    {
      Ptr<Socket> acceptedSocket = m_socketList.front ();
      m_socketList.pop_front ();
      acceptedSocket->Close ();
    }
  if (m_socket)
    {
      m_socket->Close ();
      m_socket->SetRecvCallback (MakeNullCallback<void, Ptr<Socket> > ());
    }
}

void ReceiverApp::HandleRead (Ptr<Socket> socket)
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
      m_totalRx += packet->GetSize ();
      UdpAckHeader ackheader;
      packet->PeekHeader(ackheader);
      uint32_t rxd_seq=ackheader.GetSequenceNumber().GetValue();
      if (InetSocketAddress::IsMatchingType (from))
        {
//          NS_LOG_UNCOND (Simulator::Now ().GetSeconds ()<<" Node: "<<m_node->GetId()
//                       << " Receive App received "
//                       <<  packet->GetSize () << " bytes from "
//                       << InetSocketAddress::ConvertFrom(from).GetIpv4 ()
//                       << " port " << InetSocketAddress::ConvertFrom (from).GetPort ()
//                       << " total Rx " << m_totalRx << " bytes");
//					   	 <<" packet with seq num:"<<(rxd_seq-1)/536);

//          Caching...
 // At destination there is no probability business as the file has reached the destination. To track the number of packets, we simply cache the packet with probability 1
		  CachePacket((rxd_seq-1)/536);
//	  	  AsciiTraceHelper ascii;
//	  	  Ptr<OutputStreamWrapper> stream_packToseq = ascii.CreateFileStream("packetidToSeq.txt",std::ios::app);
//	  	  *stream_packToseq->GetStream()<<"PacketId: "<<packet->GetUid()<<",SequenceNum:"<<ackheader.GetSequenceNumber()<<std::endl;

//          sending back the acknowledgment for the received packet
          Ptr<Packet> newPacket = Create<Packet> ();
          UdpAckHeader newackheader;	//= Create <UdpAckHeader>();
          newackheader.SetAckNumber(ackheader.GetSequenceNumber());
//          NS_LOG_UNCOND("Sending acknowledgment for : "<<newackheader.GetAckNumber());
		  newPacket->AddHeader(newackheader);

		  socket->SendTo(newPacket,0,from);

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


void ReceiverApp::HandlePeerClose (Ptr<Socket> socket)
{
  NS_LOG_FUNCTION (this << socket);
}

void ReceiverApp::HandlePeerError (Ptr<Socket> socket)
{
  NS_LOG_FUNCTION (this << socket);
}


void ReceiverApp::HandleAccept (Ptr<Socket> s, const Address& from)
{
  NS_LOG_FUNCTION (this << s << from);
  s->SetRecvCallback (MakeCallback (&ReceiverApp::HandleRead, this));
  m_socketList.push_back (s);
}

void
ReceiverApp::CachePacket(uint32_t packet_index)
{
	if(GetNode()->SearchCache(packet_index)==-1)
		GetNode()->AddtoCache(packet_index);
	NS_LOG_UNCOND("Destination "<< GetNode()->GetId()<< " storing "<<packet_index<<" to cache");
}


//##################################################################
void
MyApp::Setup (Ipv4Address addr, Ptr<Node> node)
{
  TypeId tid = TypeId::LookupByName (socketid);
  m_local = addr;
  m_tid=tid;
}


void MyApp::StartApplication ()    // Called at time specified by Start
{
  NS_LOG_FUNCTION (this);
  // Create the socket if not already
  if (!m_socket)
    {
      m_socket = Socket::CreateSocket (GetNode(), m_tid);
//      NS_LOG_UNCOND("Node: "<<node->GetId()<<"\tConnection: "<<tid);
      InetSocketAddress local = InetSocketAddress (Ipv4Address::GetAny (), port);
      NS_LOG_UNCOND("Created socket at "<<GetNode()->GetId());
      m_socket->Bind (local);
    }
      m_socket->SetRecvCallback (MakeCallback (&MyApp::HandleRead, this));
}

void MyApp::StopApplication ()     // Called at time specified by Stop
{
  NS_LOG_FUNCTION (this);
  while(!m_socketList.empty ()) //these are accepted sockets, close them
    {
      Ptr<Socket> acceptedSocket = m_socketList.front ();
      m_socketList.pop_front ();
      acceptedSocket->Close ();
    }
  if (m_socket)
    {
      m_socket->Close ();
      m_socket->SetRecvCallback (MakeNullCallback<void, Ptr<Socket> > ());
    }
}

void
MyApp::CachePacket(uint32_t packet_index,Ptr<Node> node)
{
	if(GetNode()->SearchCache(packet_index)==-1)
		node->AddtoCache(packet_index);
	NS_LOG_UNCOND(Simulator::Now().GetSeconds()<<" Node:"<<node->GetId()<<" storing "<<packet_index<<" to cache");
}


void
MyApp::PrintReceivedPacket (Ptr<Socket> socket, Ptr<Packet> packet)
{
  SocketAddressTag tag;
  bool found = packet->PeekPacketTag (tag);

  std::ostringstream oss;
  AsciiTraceHelper ascii;
  Ptr<OutputStreamWrapper> stream_rx = ascii.CreateFileStream("first_routing.txt",std::ios::app);

  oss << Simulator::Now ().GetSeconds () << " Node:" << socket->GetNode()->GetId ()<<" received";
  if (found)
    {
      InetSocketAddress addr = InetSocketAddress::ConvertFrom (tag.GetAddress ());
//      oss << " received one packet from " << addr.GetIpv4 ()<<"\tPacket: "<<packet->GetUid()<<" data:"<<int(buff[1])<<int(buff[0])<<packet->ToString();
      if(socket->GetNode()->GetId()==0)
    	  {
			  *stream_rx->GetStream()<< Simulator::Now ().GetSeconds ()
				  <<",Route:0"<<", Node:"<<socket->GetNode()->GetId()
				  <<",Destination:10.1.1.1" << ",Source:" << addr.GetIpv4 ()
				  << ",packet:" << packet->GetUid ()<<std::endl;
    	  }
    }
//  NS_LOG_UNCOND(oss.str ());
}

void
MyApp::HandleRead (Ptr<Socket> socket)
{
  Ptr<Packet> packet;
  Address from;
  while ((packet = socket->RecvFrom(from)))
    {
      packetsReceived += 1;

      UdpAckHeader ackheader;
      packet->PeekHeader(ackheader);
      uint32_t rxd_seq=ackheader.GetSequenceNumber().GetValue();

      NS_LOG_UNCOND(Simulator::Now ().GetSeconds () << " Node:" << socket->GetNode()->GetId ()
    		  <<" receiving data "<<(rxd_seq-1)/536
			  <<" from "<<InetSocketAddress::ConvertFrom(from).GetIpv4 ());

      // caching with probability 'prob'
      double min = 0.0;
      double max = 1.0;
      Ptr<UniformRandomVariable> x = CreateObject<UniformRandomVariable> ();
      if(x->GetValue(min,max)<prob)
    	  CachePacket((rxd_seq-1)/536,socket->GetNode());

      PrintReceivedPacket (socket, packet);
    }
}

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

void
CachePrint(Ptr<Node> node)
{
	AsciiTraceHelper ascii;
	Ptr<OutputStreamWrapper> stream_cache = ascii.CreateFileStream("CachedPackets.txt",std::ios::app);
	node->PrintCache();
	std::ostringstream stream;
	node->ReadCache(stream);
	*stream_cache->GetStream()<<stream.str();
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
	NqosWifiMacHelper wifiMac = NqosWifiMacHelper::Default ();
	wifi.SetRemoteStationManager ("ns3::ConstantRateWifiManager",
								  "DataMode",StringValue ("DsssRate1Mbps"),
								  "ControlMode",StringValue ("DsssRate1Mbps"));
	wifiPhy.Set ("TxPowerStart",DoubleValue (txp));
	wifiPhy.Set ("TxPowerEnd", DoubleValue (txp));
	wifiMac.SetType ("ns3::AdhocWifiMac");

	NetDeviceContainer devices = wifi.Install (wifiPhy, wifiMac, nodes);
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
	Ipv4AddressHelper address;
	list.Add(aodv_routing,50);
	internet_stack.SetRoutingHelper(list);
	internet_stack.Install(nodes);
	address.SetBase ("10.1.1.0", "255.255.255.0");
	Ipv4InterfaceContainer interfaces = address.Assign (devices);


    AsciiTraceHelper ascii;
    Ptr<OutputStreamWrapper> stream_broadcast = ascii.CreateFileStream ("fifth_broadcast.txt");
    Ptr<OutputStreamWrapper> stream_unicast = ascii.CreateFileStream ("fifth_unicast.txt");
    std::ostringstream oss;
    oss << "/NodeList/*/$ns3::Ipv4L3Protocol/LocalDeliveryWithNode";
    Config::Connect(oss.str (), MakeBoundCallback (&LocalDelivery,stream_broadcast,stream_unicast));

// Setting up the application

//    uint16_t sinkPort = 9;
    Address sinkAddress  (InetSocketAddress (interfaces.GetAddress (manet_DestnId ), port ));
    Address sourceAddress(InetSocketAddress (interfaces.GetAddress (manet_sourceId), port1));
    Ptr<Node> sinkNode=nodes.Get(manet_DestnId);
//	Setting up source application
    TypeId tid1 = TypeId::LookupByName (socketid);
    Ptr<Socket> ns3Socket = Socket::CreateSocket (nodes.Get (manet_sourceId), tid1);
    Ptr<SendApp> sendapp = CreateObject<SendApp> ();
    sendapp->Setup (ns3Socket, sinkAddress, sourceAddress, 1040, nPackets, DataRate ("1000Kbps"));
    nodes.Get (manet_sourceId)->AddApplication (sendapp);
    sendapp->SetStartTime (Seconds (5.));
    sendapp->SetStopTime(stop_time);
//	Setting up sink application
    uint8_t sink_id=manet_DestnId;
	Ptr<ReceiverApp> rxrapp = CreateObject<ReceiverApp> ();
	rxrapp->Setup (tid1,sinkAddress);
	nodes.Get(sink_id)->AddApplication (rxrapp);
	rxrapp->SetStartTime (app_start+Seconds(sink_id));
	rxrapp->SetStopTime (app_stop);

//	setting up the intermediate nodes.
//	Note: This requires local delivery callback from aodvroutingprotocol.cc inside route input
//	uint32_t j=2;
    for (uint32_t j=0;j<nNodes;j++)
    	if((j!=manet_DestnId)&&(j!=manet_sourceId))
    	{
    		Ptr<MyApp> myapp = CreateObject<MyApp> ();
    		myapp->Setup (interfaces.GetAddress (manet_DestnId), nodes.Get (j));
    		nodes.Get(j)->AddApplication(myapp);
    		myapp->SetStartTime (app_start+Seconds(0.1*j));
			myapp->SetStopTime (app_stop);
    	}


    devices.Get (0)->TraceConnectWithoutContext ("PhyRxDrop", MakeCallback (&RxDrop));

//    Ptr<OutputStreamWrapper> stream_rx = ascii.CreateFileStream("fifth_received.txt");
    Ptr<OutputStreamWrapper> stream = ascii.CreateFileStream("first_routing.txt");
    Ptr<OutputStreamWrapper> stream_mob = ascii.CreateFileStream("fifth_mobility.txt");
    Ptr<OutputStreamWrapper> stream_dat = ascii.CreateFileStream("manet_config.txt");
    Ptr<OutputStreamWrapper> stream_routing = ascii.CreateFileStream("aodv_routing_table.txt");
    Ptr<OutputStreamWrapper> stream_seqtopack = ascii.CreateFileStream("packetidToSeq.txt");
    Ptr<OutputStreamWrapper> stream_cache = ascii.CreateFileStream("CachedPackets.txt");

    *stream_dat->GetStream()<<"NNodes:"<<nNodes<<"\nnSpeed:"<<nSpeed<<"\nXRange:"<<xRange<<"\nYRange:"<<yRange;
    *stream_dat->GetStream()<<"\nDestn ID:"<<manet_DestnId<<"\nSource Id:"<<manet_sourceId<<"\nNPackets:"<<nPackets;

    aodv_routing.PrintRoutingTableAllAt(Seconds(0),stream_routing);
    aodv_routing.PrintRoutingTableAllEvery(Seconds(1),stream_routing);
//    MobilityAutoCheck ();

    for (uint8_t i=0;i<nNodes;i++)
    	Simulator::Schedule (stop_time-Seconds (.1), &CachePrint,nodes.Get(i));
    AnimationInterface anim("fifth_manet.xml");

    Simulator::Stop (stop_time);
    Simulator::Run ();
    Simulator::Destroy ();

  return 0;
}

