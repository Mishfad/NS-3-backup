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

#include "ns3/tcp-tx-buffer.h"

namespace ns3 {


//NS_LOG_COMPONENT_DEFINE ("manetudpwithack");

// ===========================================================================

uint16_t packetsReceived=0;
uint16_t port = 8080;
uint16_t port1 = 9090;
std::string socketid="ns3::UdpSocketFactory";

std::string manet_destn="10.1.1.1";
//Ipv4Address manet_destn("10.1.1.1");
Ipv4Address dst = Ipv4Address ("10.1.1.1");
Ipv4Address src = Ipv4Address ("10.1.1.12");

uint8_t manet_sourceId=11;
uint8_t manet_DestnId=0;
uint8_t nNodes=20;
uint32_t nPackets=50;
uint32_t PacketSize=100;

double nSpeed=40; // in m/s
uint32_t xRange=1500;
uint32_t yRange=1500;
double txp=1;
double prob=1;
Time start_time=Seconds (0);
Time stop_time=Seconds (90);
Time app_start=Seconds (0);
Time app_stop=Seconds (90);

//##################################################################
//##################################################################

class UdpAckHeader : public Header
{
public:
	UdpAckHeader ();
	virtual ~UdpAckHeader ();
	virtual TypeId GetInstanceTypeId (void) const;
	virtual void Print (std::ostream &os) const;
	virtual uint32_t GetSerializedSize (void) const;
	virtual void Serialize (Buffer::Iterator start) const; // VERY IMPORTANT FUNCTIONs
	virtual uint32_t Deserialize (Buffer::Iterator start); // - need to edit these if you add a new variable

	void SetSequenceNumber (SequenceNumber32 sequenceNumber);
	void SetAckNumber (SequenceNumber32 ackNumber);
	SequenceNumber32 GetSequenceNumber () const;
	SequenceNumber32 GetAckNumber () const;
	void SetDestinationPort (uint16_t port);
	void SetSourcePort (uint16_t port);
	uint16_t GetSourcePort (void) const;
	uint16_t GetDestinationPort (void) const;
	Address GetSourceAddress (void) const;
	bool GetBroadcastFlag(void);
	void SetBroadcastFlag(bool val);
	bool GetAckFlag(void);
	void SetAckFlag(bool val);

	void InitializeChecksum (Address source, Address destination);

private:
	bool m_broadcastFlag;			// if true when received, broadcast it and set to false
	bool m_AckFlag;			// if true the packet is an acknowledgement packet, and if false the packet is a data packet
	SequenceNumber32 m_sequenceNumber;  //!< Sequence number
	SequenceNumber32 m_ackNumber;       //!< ACK number

	uint16_t m_sourcePort;      //!< Source port
	uint16_t m_destinationPort; //!< Destination port

	Address m_source;           //!< Source IP address
	Address m_destination;      //!< Destination IP address

};

class SendApp : public Application
{
public:

  SendApp ();
  virtual ~SendApp();

  void Setup (Ptr<Socket> socket, Address sinkAddress, Address sourceAddress, uint32_t packetSize, uint32_t nPackets, DataRate dataRate);
	uint16_t m_count;

private:
  virtual void StartApplication (void);
  virtual void StopApplication (void);

  void ScheduleTx (void);
  void SendPacket (void);
  void SendPendingPackets(void);
  uint32_t  SendDataPacket (SequenceNumber32 seq, uint32_t maxSize);
  void ReTxTimeout (void);
  void Retransmit (void);
  void SendPackettoNeighbors(Ptr<Packet> p);

  void SetnNeighbors(uint8_t n);
  uint8_t GetnNeighbors(void);
  uint8_t* FindNeighbors(void);
  void ProcessReceivedAckPacket(Ptr<Packet> p);

//  void CreateReceiveSocket(void);

  void HandleRead (Ptr<Socket> socket);
  void HandlePeerClose (Ptr<Socket> socket);
  void HandlePeerError (Ptr<Socket> socket);
  void HandleAccept (Ptr<Socket> s, const Address& from);


  Ptr<Socket>     m_socket;
  Ptr<Socket>     m_receivesocket;
  Address         m_peer;
  Address         m_local;
  uint32_t        m_packetSize;
  uint32_t        m_nPackets;
  DataRate        m_dataRate;
  EventId         m_sendEvent;
  bool            m_running;
  uint32_t        m_npacketsSent; // no of packets sent
  uint32_t        m_npacketstoBuf; // no of packets added to buffer
  uint8_t 		  m_nNeighbors;


  SequenceNumber32 m_seqNumber;
  SequenceNumber32 m_lastAcknowledgedNumber;
  uint32_t		   m_windowSize;

  TracedValue<SequenceNumber32> m_nextTxSequence; //!< Next seqnum to be sent (SND.NXT), ReTx pushes it back
  TracedValue<SequenceNumber32> m_highTxMark;     //!< Highest seqno ever sent, regardless of ReTx
  Ptr<TcpTxBuffer>              m_txBuffer;       //!< Tx buffer

  EventId           m_retxEvent;       //!< Retransmission event
  TracedValue<Time> m_rto;             //!< Retransmit timeout
  SequenceNumber32  m_recover;      //!< Previous highest Tx seqnum for fast recovery
  uint32_t          m_retransOut;   //!< Number of retransmission in this window

};

//#############################################################################################
//
//#############################################################################################

class ReceiverApp : public Application
{
public:
  ReceiverApp ();
  virtual ~ReceiverApp ();

  void Setup (TypeId tid,Address address);
 private:
  virtual void StartApplication (void);    // Called at time specified by Start
  virtual void StopApplication (void);     // Called at time specified by Stop
  /**
   * \brief Handle a packet received by the application
   * \param socket the receiving socket
   */
  void HandleRead (Ptr<Socket> socket);
  /**
   * \brief Handle an incoming connection
   * \param socket the incoming connection socket
   * \param from the address the connection is from
   */
  void HandleAccept (Ptr<Socket> socket, const Address& from);
  /**
   * \brief Handle an connection close
   * \param socket the connected socket
   */
  void HandlePeerClose (Ptr<Socket> socket);
  /**
   * \brief Handle an connection error
   * \param socket the connected socket
   */
  void HandlePeerError (Ptr<Socket> socket);

  void CachePacket(uint32_t);
  void ProcessReceivedPacket(Ptr<Socket> socket, Ptr<Packet> packet, Address from);

  // In the case of TCP, each socket accept returns a new socket, so the
  // listening socket is stored separately from the accepted sockets
  Ptr<Socket>     m_socket;       //!< Listening socket
  std::list<Ptr<Socket> > m_socketList; //!< the accepted sockets

  Address         m_local;        //!< Local address to bind to
  Address         m_peer;        //!< peer address to send the packet to
  uint32_t        m_totalRx;      //!< Total bytes received
  TypeId          m_tid;          //!< Protocol TypeId
//  Ptr<Node> 	  m_sinknode;	  // Sink node pointer (to create a socket at every receiving node)

  /// Traced Callback: received packets, source address.
  TracedCallback<Ptr<const Packet>, const Address &> m_rxTrace;

};


class MyApp: public Application
{
public:

	void Setup (Ipv4Address addr, Ptr<Node> node);
	void CachePacket(uint32_t packet_index,Ptr<Node> node);
	void PrintReceivedPacket (Ptr<Socket> socket, Ptr<Packet> packet);
	void HandleRead (Ptr<Socket> socket);
	void SetnNeighbors(uint8_t n);
	uint8_t GetnNeighbors(void);
	uint8_t* FindNeighbors(void);
	void SendPackettoNeighbors(Ptr<Packet> p);
	void SendAckTo(Ptr<Socket> socket, Address from, UdpAckHeader ackheader);


	virtual void StartApplication (void);    // Called at time specified by Start
	virtual void StopApplication (void);     // Called at time specified by Stop

private:
	Ptr<Socket>     m_socket;       //!< Listening socket
	std::list<Ptr<Socket> > m_socketList; //!< the accepted sockets

	Ipv4Address         m_local;        //!< Local address to bind to
	TypeId          	m_tid;          //!< Protocol TypeId
	uint8_t 		    m_nNeighbors;


};

int SearchArray(uint8_t* array,uint8_t length, uint8_t val)
	{
//		NS_LOG_UNCOND("search key: "<<int(val));
		for(uint8_t i=0;i<length;i++)
		{
//			NS_LOG_UNCOND("array["<<int(i)<<"]="<<int(array[i]));
			if(array[i]==val)
				return i;
		}
		return -1;
	}
}
