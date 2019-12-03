# Lab 3 (using lab 3 Skeleton)
# Connor Monson
# cmonson
# cmonson@ucsc.edu
# CMPE 150/L
# Based on of_tutorial by James McCauley

from pox.core import core
import pox.openflow.libopenflow_01 as of #POX convention
# *** !!! maybe more imports !!! ***
import pox.lib.packet as pkt  #POX convention

log = core.getLogger()

class Firewall (object):
  """
  A Firewall object is created for each switch that connects.
  A Connection object for that switch is passed to the __init__ function.
  """
  def __init__ (self, connection):
    # Keep track of the connection to the switch so that we can
    # send it messages!
    self.connection = connection

    # This binds our PacketIn event listener
    connection.addListeners(self)

# *** !!! need to do this !!! ***
  def do_firewall (self, packet, packet_in):
    # The code in here will be executed for every packet.

    #The rules that you will need to implement in OpenFlow for this assignment are:

    # src ip    dst ip     protocol  action
    # any ipv4  any ipv4   tcp       accept 
    # any       any        arp       accept
    # any ipv4  any ipv4    -        drop 

    msg = of.ofp_flow_mod()

    #When using from_packet() with an ofp_packet_in, the in_port is taken from there by default.
    msg.match = of.ofp_match.from_packet(packet)
    msg.idle_timeout = 40
    msg.hard_timeout = 60

    #**** used as reference *******#
    #def handle_IP_packet (packet):
    #  ip = packet.find('ipv4')
    #  if ip is None:
        # This packet isn't IP!
    #    return
    #  print "Source IP:", ip.srcip
    #******************************#

    ipForIPV4 = packet.find('ipv4')
    # if ipv4 then check if tcp 
    ipForTCP = packet.find('tcp')
    # if not ipv4 then check if arp
    ipForARP = packet.find('arp')
    
    if ipForIPV4 is not None:
      if ipForTCP is not None: # is TCP so accept
        msg.data = packet_in
        # msg.priority = 42
        msg.nw_proto = 6
        # msg.match.nw_dst = IPAddr("192.168.101.101")
        # msg.match.tp_dst = 80
        msg.actions.append(of.ofp_action_output(port = of.OFPP_ALL))
        self.connection.send(msg)
      else: #otherwise drop 
        msg.data = packet_in
        self.connection.send(msg)
    else:
      if ipForARP is not None: # if ARP accept
        msg.data = packet_in
        # msg.priority = 42
        # msg.match.dl_type = 0x800
        msg.match.dl_type = 0x806
        # msg.match.nw_dst = IPAddr("192.168.101.101")
        # msg.match.tp_dst = 80
        msg.actions.append(of.ofp_action_output(port = of.OFPP_ALL))
        self.connection.send(msg)
      else: #otherwise drop
        msg.data = packet_in
        self.connection.send(msg)
  

    print "Example Code."

  def _handle_PacketIn (self, event):
    """
    Handles packet in messages from the switch.
    """

    packet = event.parsed # This is the parsed packet data.
    if not packet.parsed:
      log.warning("Ignoring incomplete packet")
      return

    packet_in = event.ofp # The actual ofp_packet_in message.
    self.do_firewall(packet, packet_in)

def launch ():
  """
  Starts the component
  """
  def start_switch (event):
    log.debug("Controlling %s" % (event.connection,))
    Firewall(event.connection)
  core.openflow.addListenerByName("ConnectionUp", start_switch)
