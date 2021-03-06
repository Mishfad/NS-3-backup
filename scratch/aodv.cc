/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2009 IITP RAS
 *
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
 *
 * This is an example script for AODV manet routing protocol.
 *
 * Authors: Pavel Boyko <boyko@iitp.ru>
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

//#include "ns3/aodv-module.h"
//#include "ns3/core-module.h"
//#include "ns3/common-module.h"
//#include "ns3/node-module.h"
//#include "ns3/helper-module.h"
//#include "ns3/mobility-module.h"
//#include "ns3/contrib-module.h"
//#include "ns3/wifi-module.h"
#include "ns3/v4ping-helper.h"
#include <iostream>
#include <cmath>

using namespace ns3;

enum TrafficType
{
  PING = 1,
  UDP = 2,
  TCP = 3
};

/**
 * \brief Test script.
 *
 * This script creates 1-dimensional grid topology and then ping last node from the first one:
 *
 * [10.0.0.1] <-- step --> [10.0.0.2] <-- step --> [10.0.0.3] <-- step --> [10.0.04]
 *
 * ping 10.0.0.4
 */
class AodvExample
{
public:
  AodvExample ();
  /// Configure script parameters, \return true on successful configuration
  bool Configure (int argc, char **argv);
  /// Run simulation
  void Run ();
  /// Report results
  void Report (std::ostream & os);

private:
  ///\name parameters
  //\{
  /// Number of nodes
  uint32_t size;
  /// Distance between nodes, meters
  double step;
  /// Simulation time, seconds
  double totalTime;
  /// Write per-device PCAP traces if true
  bool pcap;
  /// Traffic type
  uint16_t type;
  //\}

  ///\name network
  //\{
  NodeContainer nodes;
  NetDeviceContainer devices;
  Ipv4InterfaceContainer interfaces;
  //\}

private:
  void CreateNodes ();
  void CreateDevices ();
  void InstallInternetStack ();
  void InstallApplications ();
};

int main (int argc, char **argv)
{
  AodvExample test;
  if (! test.Configure(argc, argv))
    NS_FATAL_ERROR ("Configuration failed. Aborted.");

  test.Run ();
  test.Report (std::cout);
  return 0;
}

//-----------------------------------------------------------------------------
AodvExample::AodvExample () :
  size (10),
  step (120),
  totalTime (10),
  pcap (true),
  type (TCP)
{
}

bool
AodvExample::Configure (int argc, char **argv)
{
  // Enable AODV logs by default. Comment this if too noisy
  // LogComponentEnable("AodvRoutingProtocol", LOG_LEVEL_ALL);

  SeedManager::SetSeed(12345);
  CommandLine cmd;

  cmd.AddValue ("pcap", "Write PCAP traces.", pcap);
  cmd.AddValue ("type", "Traffic type.", type);
  cmd.AddValue ("size", "Number of nodes.", size);
  cmd.AddValue ("time", "Simulation time, s.", totalTime);
  cmd.AddValue ("step", "Grid step, m", step);

  cmd.Parse (argc, argv);
  return true;
}

void
AodvExample::Run ()
{
//  Config::SetDefault ("ns3::WifiRemoteStationManager::RtsCtsThreshold", UintegerValue (1)); // enable rts cts all the time.
  CreateNodes ();
  CreateDevices ();
  InstallInternetStack ();
  InstallApplications ();

  std::cout << "Starting simulation for " << totalTime << " s ...\n";

  Simulator::Stop (Seconds (totalTime));
  Simulator::Run ();
  Simulator::Destroy ();
}

void
AodvExample::Report (std::ostream &)
{
}

void
AodvExample::CreateNodes ()
{
  std::cout << "Creating " << (unsigned)size << " nodes " << step << " m apart.\n";
  nodes.Create (size);
  // Name nodes
  for (uint32_t i = 0; i < size; ++i)
     {
       std::ostringstream os;
       os << "node-" << i;
       Names::Add (os.str (), nodes.Get (i));
     }
  // Create static grid
  MobilityHelper mobility;
  mobility.SetPositionAllocator ("ns3::GridPositionAllocator",
                                "MinX", DoubleValue (0.0),
                                "MinY", DoubleValue (0.0),
                                "DeltaX", DoubleValue (step),
                                "DeltaY", DoubleValue (0),
                                "GridWidth", UintegerValue (size),
                                "LayoutType", StringValue ("RowFirst"));
  mobility.SetMobilityModel ("ns3::ConstantPositionMobilityModel");
  mobility.Install (nodes);
}

void
AodvExample::CreateDevices ()
{
  NqosWifiMacHelper wifiMac = NqosWifiMacHelper::Default ();
  wifiMac.SetType ("ns3::AdhocWifiMac");
  YansWifiPhyHelper wifiPhy = YansWifiPhyHelper::Default ();
  YansWifiChannelHelper wifiChannel = YansWifiChannelHelper::Default ();
  wifiPhy.SetChannel (wifiChannel.Create ());
  WifiHelper wifi = WifiHelper::Default ();
  wifi.SetRemoteStationManager ("ns3::ConstantRateWifiManager", "DataMode", StringValue ("DsssRate1Mbps"), "RtsCtsThreshold", UintegerValue (0));
  devices = wifi.Install (wifiPhy, wifiMac, nodes);

  if (pcap)
    {
      wifiPhy.EnablePcapAll (std::string ("aodv"));
    }
}

void
AodvExample::InstallInternetStack ()
{
  AodvHelper aodv;
  // you can configure AODV attributes here using aodv.Set(name, value)
  InternetStackHelper stack;
  stack.SetRoutingHelper (aodv);
  stack.Install (nodes);
  Ipv4AddressHelper address;
  address.SetBase ("10.0.0.0", "255.0.0.0");
  interfaces = address.Assign (devices);
}

void
AodvExample::InstallApplications ()
{
  switch (type)
  {
    case PING:
      {
        V4PingHelper ping (interfaces.GetAddress(size - 1));
        ping.SetAttribute ("Verbose", BooleanValue (true));

        ApplicationContainer p = ping.Install (nodes.Get (0));
        p.Start (Seconds (0));
        p.Stop (Seconds (totalTime));
        break;
      }
    case UDP:
      {
        // Create the OnOff application to send UDP datagrams of size
        // 210 bytes at a rate of 448 Kb/s
        Config::SetDefault ("ns3::OnOffApplication::PacketSize", UintegerValue (210));
        Config::SetDefault ("ns3::OnOffApplication::DataRate", DataRateValue (DataRate ("448kb/s")));
        uint16_t port = 9; // Discard port (RFC 863)

        OnOffHelper onoff ("ns3::UdpSocketFactory",
            Address (InetSocketAddress ("10.255.255.255", port)));
        onoff.SetAttribute ("OnTime", StringValue ("ns3::ConstantRandomVariable[Constant=1.0]"));
        onoff.SetAttribute ("OffTime", StringValue ("ns3::ConstantRandomVariable[Constant=0]"));

        ApplicationContainer apps = onoff.Install (nodes.Get (0));
        apps.Start(Seconds(0));
        apps.Stop (Seconds(totalTime));

        // Create an optional packet sink to receive these packets
        PacketSinkHelper sink ("ns3::UdpSocketFactory",
            Address (InetSocketAddress (Ipv4Address::GetAny (), port)));
        for (uint32_t i = 1; i < nodes.GetN (); ++i)
          {
            apps.Add(sink.Install (nodes.Get (i)) );
          }
        apps.Start (Seconds (0));
        apps.Stop (Seconds (totalTime));
        break;
      }
    case TCP:
         {
//           V4PingHelper ping (interfaces.GetAddress(size - 1));
//           ping.SetAttribute ("Verbose", BooleanValue (true));
//
//           ApplicationContainer p = ping.Install (nodes.Get (0));
//           p.Start (Seconds (0));
//           p.Stop (Seconds (totalTime/2));


           Config::SetDefault ("ns3::OnOffApplication::PacketSize", UintegerValue (4096));
           Config::SetDefault ("ns3::OnOffApplication::DataRate", StringValue ("6Mbps"));

           uint16_t port = 8080;
           PacketSinkHelper sinkHelper ("ns3::TcpSocketFactory", InetSocketAddress (Ipv4Address::GetAny (), port));
           ApplicationContainer sinkApp = sinkHelper.Install (nodes.Get (size-1));
           sinkApp.Start (Seconds (totalTime/2));
           sinkApp.Stop (Seconds (totalTime));

           // Create the OnOff applications to send TCP
           OnOffHelper clientHelper ("ns3::TcpSocketFactory", Address ());
           clientHelper.SetAttribute
               ("OnTime", StringValue ("ns3::ConstantRandomVariable[Constant=1.0]"));
           clientHelper.SetAttribute
               ("OffTime", StringValue ("ns3::ConstantRandomVariable[Constant=0]"));

           ApplicationContainer clientApp;
           AddressValue remoteAddress
               (InetSocketAddress (interfaces.GetAddress (size-1), port));
           clientHelper.SetAttribute ("Remote", remoteAddress);
           clientApp = clientHelper.Install (nodes.Get (0));
           clientApp.Start (Seconds (totalTime/2));
           clientApp.Stop (Seconds (totalTime));

         }

  };

}
