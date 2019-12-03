# Connor Monson
# cmonson
# cmonson@ucsc.edu
# CMPE 150/L
# Final Skeleton
#
# Hints/Reminders from Lab 3:
#
# To check the source and destination of an IP packet, you can use
# the header information... For example:
#
# ip_header = packet.find('ipv4')
#
# if ip_header.srcip == "1.1.1.1":
#   print "Packet is from 1.1.1.1"
#
# Important Note: the "is" comparison DOES NOT work for IP address
# comparisons in this way. You must use ==.
# 
# To send an OpenFlow Message telling a switch to send packets out a
# port, do the following, replacing <PORT> with the port number the 
# switch should send the packets out:
#
#    msg = of.ofp_flow_mod()
#    msg.match = of.ofp_match.from_packet(packet)
#    msg.idle_timeout = 30
#    msg.hard_timeout = 30
#
#    msg.actions.append(of.ofp_action_output(port = <PORT>))
#    msg.data = packet_in
#    self.connection.send(msg)
#
# To drop packets, simply omit the action.
#

from pox.core import core
import pox.openflow.libopenflow_01 as of
import pox.lib.packet as pkt 

log = core.getLogger()

class Final (object):
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

  def do_final (self, packet, packet_in, port_on_switch, switch_id):
    # This is where you'll put your code. The following modifications have 
    # been made from Lab 3:
    #   - port_on_switch: represents the port that the packet was received on.
    #   - switch_id represents the id of the switch that received the packet.
    #      (for example, s1 would have switch_id == 1, s2 would have switch_id == 2, etc...)
    # You should use these to determine where a packet came from. To figure out where a packet 
    # is going, you can use the IP header information.
    
    #ICMP traffic is a type of IP traffic
    #everything goes through switch 4 
      #check if IP traffic 
        #if true -> check if ICMP traffic
          #if ICMP traffic -> check if it is coming from host4
            #if true -> do not allow 
            #if false -> allow traffic communication
          #if NOT ICMP traffic -> check if host4 is trying to send it to the server (host5)
            #if true -> do not allow (dont allow host4 send IP traffic to host5)
            #if false -> allow traffic communication
        #if false (Not IP traffic) -> flood  

    msg = of.ofp_flow_mod()
    #msg.match = of.ofp_match.from_packet(packet)
    msg.idle_timeout = 40
    msg.hard_timeout = 60
    ip = packet.find('ipv4')
    ICMP = packet.find('icmp')
    port = 0

    if ip is not None: 
      #print "PASS: ip is not NONE! "
      #msg = of.ofp_flow_mod()
      msg.match = of.ofp_match.from_packet(packet)
      if ICMP is not None:

        if switch_id == 4:
          if ip.srcip == "123.45.67.89" and ip.dstip == "10.1.1.10":
            msg.data = packet_in
            self.connection.send(msg)
            print "dropped. ICMP 1: h4->h1"
          elif ip.srcip == "123.45.67.89" and ip.dstip == "10.2.2.20":
            msg.data = packet_in
            self.connection.send(msg)
             print "dropped. ICMP 2: h4->h2"
          elif ip.srcip == "123.45.67.89" and ip.dstip == "10.3.3.30":
            msg.data = packet_in
            self.connection.send(msg)
            print "dropped. ICMP 3: h4->h3"
          elif ip.srcip == "123.45.67.89" and ip.dstip == "10.5.5.50":
            msg.data = packet_in
            self.connection.send(msg)
            print "dropped. ICMP 4: h4->h5"
          elif ip.dstip == "10.1.1.10":
            port = 1
            msg.data = packet_in
            msg.actions.append(of.ofp_action_output(port = port))
            self.connection.send(msg)
          elif ip.dstip == "10.2.2.20":
            port = 2
            msg.data = packet_in
            msg.actions.append(of.ofp_action_output(port = port))
            self.connection.send(msg)
          elif ip.dstip == "10.3.3.30":
            port = 3
            msg.data = packet_in
            msg.actions.append(of.ofp_action_output(port = port))
            self.connection.send(msg)
          elif ip.dstip == "123.45.67.89":
            print "ICMP: destination host 4, code was reached"
            port = 8
            msg.data = packet_in
            msg.actions.append(of.ofp_action_output(port = port))
            self.connection.send(msg)
          elif ip.dstip == "10.5.5.50":
            port = 5
            msg.data = packet_in
            msg.actions.append(of.ofp_action_output(port = port))
            self.connection.send(msg)
        elif switch_id == 1: 
          if ip.dstip == "10.1.1.10":
            port = 8
            msg.data = packet_in
            msg.actions.append(of.ofp_action_output(port = port)) #take out this line for dropping 
            self.connection.send(msg)
          else: #any other destination send to switch 4
            port = 1
            msg.data = packet_in
            msg.actions.append(of.ofp_action_output(port = port))
            self.connection.send(msg)

        elif switch_id == 2: 
          if ip.dstip == "10.2.2.20":
            port = 8
            msg.data = packet_in
            msg.actions.append(of.ofp_action_output(port = port)) #take out this line for dropping 
            self.connection.send(msg)
          else: #any other destination send to switch 4
            port = 1
            msg.data = packet_in
            msg.actions.append(of.ofp_action_output(port = port))
            self.connection.send(msg)

        elif switch_id == 3: 
          if ip.dstip == "10.3.3.30":
            port = 8
            msg.data = packet_in
            msg.actions.append(of.ofp_action_output(port = port)) #take out this line for dropping 
            self.connection.send(msg)
          else: #any other destination send to switch 4
            port = 1
            msg.data = packet_in
            msg.actions.append(of.ofp_action_output(port = port))
            self.connection.send(msg)

        elif switch_id == 5:
          if ip.dstip == "10.5.5.50":
            port = 8
            msg.data = packet_in
            msg.actions.append(of.ofp_action_output(port = port)) #take out this line for dropping 
            self.connection.send(msg)
          else: #any other destination send to switch 4
            port = 1
            msg.data = packet_in
            msg.actions.append(of.ofp_action_output(port = port))
            self.connection.send(msg)  

      else:
        
        # longest one is switch 4 
        if switch_id == 4:
          if ip.srcip == "123.45.67.89" and ip.dstip == "10.5.5.50":
            msg.data = packet_in
            self.connection.send(msg)
            print "dropped. IP: h4->h5"
          elif ip.dstip == "10.1.1.10":
            port = 1
            msg.data = packet_in
            msg.actions.append(of.ofp_action_output(port = port))
            self.connection.send(msg)
          elif ip.dstip == "10.2.2.20":
            port = 2
            msg.data = packet_in
            msg.actions.append(of.ofp_action_output(port = port))
            self.connection.send(msg)
          elif ip.dstip == "10.3.3.30":
            port = 3
            msg.data = packet_in
            msg.actions.append(of.ofp_action_output(port = port))
            self.connection.send(msg)
          elif ip.dstip == "123.45.67.89":
            print "IP: destination host 4, code was reached"
            port = 8
            msg.data = packet_in
            msg.actions.append(of.ofp_action_output(port = port))
            self.connection.send(msg)
          elif ip.dstip == "10.5.5.50":
            port = 5
            msg.data = packet_in
            msg.actions.append(of.ofp_action_output(port = port))
            self.connection.send(msg)

        elif switch_id == 1: 
          if ip.dstip == "10.1.1.10":
            port = 8
            msg.data = packet_in
            msg.actions.append(of.ofp_action_output(port = port)) #take out this line for dropping 
            self.connection.send(msg)
          else: #any other destination send to switch 4
            port = 1
            msg.data = packet_in
            msg.actions.append(of.ofp_action_output(port = port))
            self.connection.send(msg)

        elif switch_id == 2: 
          if ip.dstip == "10.2.2.20":
            port = 8
            msg.data = packet_in
            msg.actions.append(of.ofp_action_output(port = port)) #take out this line for dropping 
            self.connection.send(msg)
          else: #any other destination send to switch 4
            port = 1
            msg.data = packet_in
            msg.actions.append(of.ofp_action_output(port = port))
            self.connection.send(msg)

        elif switch_id == 3: 
          if ip.dstip == "10.3.3.30":
            port = 8
            msg.data = packet_in
            msg.actions.append(of.ofp_action_output(port = port)) #take out this line for dropping 
            self.connection.send(msg)
          else: #any other destination send to switch 4
            port = 1
            msg.data = packet_in
            msg.actions.append(of.ofp_action_output(port = port))
            self.connection.send(msg)

        elif switch_id == 5:
          if ip.dstip == "10.5.5.50":
            port = 8
            msg.data = packet_in
            msg.actions.append(of.ofp_action_output(port = port)) #take out this line for dropping 
            self.connection.send(msg)
          else: #any other destination send to switch 4
            port = 1
            msg.data = packet_in
            msg.actions.append(of.ofp_action_output(port = port))
            self.connection.send(msg)
    else: #drop
      #print "dropped. end"
      msg.match = of.ofp_match.from_packet(packet)
      msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
      msg.data = packet_in
      self.connection.send(msg)  

    #print "Example code."

  def _handle_PacketIn (self, event):
    """
    Handles packet in messages from the switch.
    """
    packet = event.parsed # This is the parsed packet data.
    if not packet.parsed:
      log.warning("Ignoring incomplete packet")
      return

    packet_in = event.ofp # The actual ofp_packet_in message.
    self.do_final(packet, packet_in, event.port, event.dpid)

def launch ():
  """
  Starts the component
  """
  def start_switch (event):
    log.debug("Controlling %s" % (event.connection,))
    Final(event.connection)
  core.openflow.addListenerByName("ConnectionUp", start_switch)
