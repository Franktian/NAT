/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"
#include "sr_nat.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */
    sr_nat_init(&(sr->nat));

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);
  /* fill in code here */
  print_hdrs(packet, len);

  /* This is an ARP packet */
  if (ethertype(packet) == ethertype_arp) {
    sr_handle_arp_packet(sr, packet, len, interface);
  }

  /* This is an IP packet */
  if (ethertype(packet) == ethertype_ip) {
    sr_handle_ip_packet(sr, packet, len, interface);
  }
}/* end sr_ForwardPacket */

/*---------------------------------------------------------------------
 * Method: sr_handle_arp_packet(struct sr_instance* sr,
 *            uint8_t *packet,
 *            unsigned int len,
 *            char* interface)
 * Scope:  Global
 *
 * Check if the ARP packet is ARP request or ARP reply, if ARP request,
 * then generate an ARP reply and send it back, if ARP reply, then
 * call process_arp_reply
 *
 *---------------------------------------------------------------------*/

void sr_handle_arp_packet(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

  /* Check ARP request or ARP reply */
  if (ntohs(arp_hdr->ar_op) == arp_op_request) {
      /* An ARP request, contruct an ARP reply and send it back */
      sr_send_arp_reply(sr, packet, interface);

   } else if (ntohs(arp_hdr->ar_op) == arp_op_reply) {
      sr_process_arp_reply(sr, packet);
   }
}

/*---------------------------------------------------------------------
 * Method: sr_handle_ip_packet(struct sr_instance* sr,
 *            uint8_t *packet,
 *            unsigned int len,
 *            char* interface)
 * Scope:  Global
 *
 *---------------------------------------------------------------------*/

void sr_handle_ip_packet(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) +\
                                                       sizeof(sr_ip_hdr_t));

  /* Sanity-check the packet */
  if (!sr_ip_sanity_check(packet, len, ip_hdr, icmp_hdr)) {
    return;
  }

  if (sr->enable_nat) {
    sr_nat_handle_ip_packet(sr, packet, len, interface);
    return;
  }

  /* Is this IP packet for me or not? */
  if (sr_ip_destined_for_router_interfaces(sr, ip_hdr->ip_dst)) {
    /* This packet is for me, is it ICMP Echo request or TCP/UDP? */
    if (ip_hdr->ip_p == ip_protocol_icmp) {
      sr_handle_icmp_packet(sr, packet, len, interface);
    } else if (ip_hdr->ip_p == ip_protocol_tcp || ip_hdr->ip_p == ip_protocol_udp) {
      /* IP contains TCP/UDP, send ICMP Port unreachable */
      sr_send_icmp(sr, packet, ICMP_UNREACHABLE_TYPE, ICMP_PORT_CODE);
    }

  } else {
    sr_forward_ip_packet(sr, packet, len, interface);
  }
}

void sr_handle_icmp_packet(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) +\
                                                       sizeof(sr_ip_hdr_t));

  /* If not ICMP Echo request, disgard it */
  if (icmp_hdr->icmp_type != ICMP_ECHO_REQUEST_TYPE || icmp_hdr->icmp_code != ICMP_ECHO_REQUEST_CODE)
    return;

  /* Swap the IP destination and source */
  uint32_t ip_src = ip_hdr->ip_src;
  ip_hdr->ip_src = ip_hdr->ip_dst;
  ip_hdr->ip_dst = ip_src;
  ip_hdr->ip_ttl = 64;
  ip_hdr->ip_sum = 0;
  ip_hdr->ip_sum = cksum(ip_hdr, ip_hdr->ip_hl * 4);

  /* Change the ICMP type to echo reply */
  icmp_hdr->icmp_type = ICMP_ECHO_REPLY_TYPE;
  icmp_hdr->icmp_sum = 0;
  icmp_hdr->icmp_sum = cksum(icmp_hdr, ntohs(ip_hdr->ip_len) - (ip_hdr->ip_hl * 4));

  sr_forward_ip_packet(sr, packet, len, interface);
}

void sr_nat_handle_ip_packet(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

  if (ip_hdr->ip_p == ip_protocol_icmp) {
    sr_nat_handle_icmp_packet(sr, packet, len, interface);
  } else if (ip_hdr->ip_p == ip_protocol_tcp) {
    sr_nat_handle_tcp_packet(sr, packet, len, interface);
  }
}

void sr_nat_handle_icmp_packet(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  if (strncmp(interface, INTERNAL_INTERFACE, sr_IFACE_NAMELEN) == 0) {
    sr_nat_handle_icmp_internal(sr, packet, len, interface);
  } else {
    sr_nat_handle_icmp_external(sr, packet, len, interface);
  }
}

void sr_nat_handle_icmp_internal(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  sr_icmp_echo_hdr_t *icmp_hdr = (sr_icmp_echo_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

  if (sr_ip_destined_for_router_interfaces(sr, ip_hdr->ip_dst)) {
    sr_handle_icmp_packet(sr, packet, len, interface);
  } else if (!sr_longest_prefix_match(sr, ip_hdr->ip_dst)) {
    sr_send_icmp(sr, packet, ICMP_UNREACHABLE_TYPE, ICMP_DESTINATION_NET_CODE);
  } else {
    /* An ICMP echo equest(ping) to external app servers, outbound logic starts */
    struct sr_nat_mapping *mapping = sr_nat_lookup_internal(&sr->nat, ip_hdr->ip_src, icmp_hdr->icmp_id, nat_mapping_icmp);

    /* No mapping found, create one */
    if (!mapping)
      mapping = sr_nat_insert_mapping(&sr->nat, ip_hdr->ip_src, icmp_hdr->icmp_id, nat_mapping_icmp);

    /* Translate the ICMP echo request */
    struct sr_if *ext_iface = sr_get_interface(sr, EXTERNAL_INTERFACE);

    ip_hdr->ip_src = ext_iface->ip;

    icmp_hdr->icmp_id = mapping->aux_ext;
    icmp_hdr->icmp_sum = 0;
    icmp_hdr->icmp_sum = cksum(icmp_hdr, ntohs(ip_hdr->ip_len) - (ip_hdr->ip_hl * 4));

    /* When packet reaches here, it pass all checkst and points to a valid destination */
    sr_forward_ip_packet(sr, packet, len, interface);

    free(mapping);
  }
}

void sr_nat_handle_icmp_external(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  sr_icmp_echo_hdr_t *icmp_hdr = (sr_icmp_echo_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

  if (!sr_ip_destined_for_router_interfaces(sr, ip_hdr->ip_dst)) {
    /* Received a packet from external interface not destinated for it, simply drop it */
    return;
  } else {
    /* An ICMP echo reply from external hosts, inbound logic starts */
    struct sr_nat_mapping *mapping = sr_nat_lookup_external(&(sr->nat), icmp_hdr->icmp_id, nat_mapping_icmp);

    if (!mapping) {
      sr_send_icmp(sr, packet, ICMP_UNREACHABLE_TYPE, ICMP_PORT_CODE);
      return;
    }

    ip_hdr->ip_dst = mapping->ip_int;

    icmp_hdr->icmp_id = mapping->aux_int;
    icmp_hdr->icmp_sum = 0;
    icmp_hdr->icmp_sum = cksum(icmp_hdr, ntohs(ip_hdr->ip_len) - (ip_hdr->ip_hl * 4));

    sr_forward_ip_packet(sr, packet, len, interface);

    free(mapping);
  }
  /*sr_forward_ip_packet(sr, packet, len, interface);*/
}

void sr_nat_handle_tcp_packet(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  if (strncmp(interface, INTERNAL_INTERFACE, sr_IFACE_NAMELEN) == 0) {
    sr_nat_handle_tcp_internal(sr, packet, len, interface);
  } else {
    sr_nat_handle_tcp_external(sr, packet, len, interface);
  }
}

void sr_nat_handle_tcp_internal(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  sr_tcp_hdr_t *tcp_hdr = (sr_tcp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

  print_hdr_tcp((uint8_t *)tcp_hdr);

  if (sr_ip_destined_for_router_interfaces(sr, ip_hdr->ip_dst)) {
    sr_send_icmp(sr, packet, ICMP_UNREACHABLE_TYPE, ICMP_PORT_CODE);
  } else if (!sr_longest_prefix_match(sr, ip_hdr->ip_dst)) {
    sr_send_icmp(sr, packet, ICMP_UNREACHABLE_TYPE, ICMP_DESTINATION_NET_CODE);
  } else {
    struct sr_nat_mapping *mapping = sr_nat_lookup_internal(&sr->nat, ip_hdr->ip_src, tcp_hdr->tcp_src_port, nat_mapping_tcp);

    if (!mapping)
      mapping = sr_nat_insert_mapping(&sr->nat, ip_hdr->ip_src, tcp_hdr->tcp_src_port, nat_mapping_tcp);

    /* Translate the TCP packet */
    struct sr_if *ext_iface = sr_get_interface(sr, EXTERNAL_INTERFACE);

    ip_hdr->ip_src = ext_iface->ip;

    tcp_hdr->tcp_src_port = mapping->aux_ext;
    tcp_hdr->tcp_sum = tcp_cksum(packet, len);

    sr_forward_ip_packet(sr, packet, len, interface);

    free(mapping);
  }
}

void sr_nat_handle_tcp_external(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  sr_tcp_hdr_t *tcp_hdr = (sr_tcp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

  print_hdr_tcp((uint8_t *)tcp_hdr);

  if (!sr_ip_destined_for_router_interfaces(sr, ip_hdr->ip_dst)) {
    return;
  } else {
    struct sr_nat_mapping *mapping = sr_nat_lookup_external(&(sr->nat), tcp_hdr->tcp_dst_port, nat_mapping_tcp);

    if (!mapping) {
      sr_send_icmp(sr, packet, ICMP_UNREACHABLE_TYPE, ICMP_PORT_CODE);
      return;
    }

    ip_hdr->ip_dst = mapping->ip_int;

    tcp_hdr->tcp_dst_port = mapping->aux_int;
    tcp_hdr->tcp_sum = tcp_cksum(packet, len);

    sr_forward_ip_packet(sr, packet, len, interface);

    free(mapping);
  }
}

/*---------------------------------------------------------------------
  * Method: sr_forward_ip_packet(struct sr_instance* sr,
  *            uint8_t *packet,
  *            unsigned int len,
  *            char* interface)
  * Scope:  Global
  *
  * Sanity check, decrement ttl, recompute checksum and forward the IP
  * packet based on the next-hop MAC address
  *
  *---------------------------------------------------------------------*/

void sr_forward_ip_packet(struct sr_instance* sr,
         uint8_t * packet/* lent */,
         unsigned int len,
         char* interface/* lent */)
{
  /* Get the headers */
  sr_ethernet_hdr_t *ethernet_hdr = (sr_ethernet_hdr_t *)packet;
  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

  ip_hdr->ip_ttl = ip_hdr->ip_ttl - 1;
  /* Check if time exceed */
  if (ip_hdr->ip_ttl <= 0) {
    sr_send_icmp(sr, packet, ICMP_TIME_EXCEEDED_TYPE, ICMP_TIME_EXCEEDED_CODE);
    return;
  }

  /* Decrement the TTL by 1 and recompute packet checksum */
  sr_ip_recompute_checksum(ip_hdr);

  /* Check routing table and perform LPM */
  struct sr_rt* lpm;
  lpm = sr_longest_prefix_match(sr, ip_hdr->ip_dst);

  if (lpm) {
    /* Check ARP cache for the next-hop MAC */
    struct sr_arpentry* entry;
    entry = sr_arpcache_lookup(&sr->cache, ip_hdr->ip_dst);

    if (entry) {
      /* It is there, send it */
      memcpy(ethernet_hdr->ether_dhost, entry->mac, ETHER_ADDR_LEN);

      struct sr_if *iface = sr_get_interface(sr, lpm->interface);
      memcpy(ethernet_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);
      sr_send_packet(sr, packet, len, lpm->interface);
      free(entry);
    } else {
      /* Send ARP request for the next-hop MAC address */
      struct sr_arpreq *request = sr_arpcache_queuereq(&sr->cache, ip_hdr->ip_dst, packet, len, lpm->interface);
      handle_arpreq(sr, request);
    }
  } else {
    /* Send ICMP Destination Net Unreachable */
    sr_send_icmp(sr, packet, ICMP_UNREACHABLE_TYPE, ICMP_DESTINATION_NET_CODE);
  }
}

/*---------------------------------------------------------------------
 * Method: sr_if* sr_ip_destined_for_router_interfaces(struct sr_instance* sr, uint32_t ip_dst)
 * Scope:  Global
 *
 * Check if the desination of IP packet is one of router's interfaces or
 * not, if yes, returns the corresponding interface struct
 *
 *---------------------------------------------------------------------*/

struct sr_if* sr_ip_destined_for_router_interfaces(struct sr_instance* sr, uint32_t ip_dst) {
  struct sr_if* if_walker = 0;

  if (sr->if_list == 0) {
    printf(" Interface list empty \n");
    return 0;
  }

  if_walker = sr->if_list;

  while(if_walker) {
    if (if_walker->ip == ip_dst) {
      return if_walker;
    }
    if_walker = if_walker->next;
  }

  return 0;
}

/*---------------------------------------------------------------------
 * Method: sr_ip_sanity_check(uint8_t * packet,
        unsigned int len,
        sr_ip_hdr_t *ip_hdr,
        sr_icmp_hdr_t * icmp_hdr)
 * Scope:  Global
 *
 * Check if the IP packet meet the minimum length, and verify the checksum
 * of the IP header and ICMP ip header, if IP packet fails sanity check,
 * it will be dropped
 *
 * If the IP packet is not of ICMP type, i.e. TCP or UDP, then don't check
 * ICMP checksum
 *
 *---------------------------------------------------------------------*/

int sr_ip_sanity_check(uint8_t * packet,
        unsigned int len,
        sr_ip_hdr_t *ip_hdr,
        sr_icmp_hdr_t * icmp_hdr)
{
  uint16_t ip_received_sum, icmp_received_sum;

  if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t)) {
    printf("IP packet does not meet minimum length requirement!\n");
    return 0;
  }

  /* Ensure IP header has correct checksum */
  ip_received_sum = ip_hdr->ip_sum;
  ip_hdr->ip_sum = 0;

  if (!cksum(ip_hdr, ip_hdr->ip_hl * 4) == ip_received_sum) {
    printf("IP header does not pass checksum check\n");
    return 0;
  }

  ip_hdr->ip_sum = ip_received_sum;

  /* TCP or UDP, don't check ICMP checksum, packet is already valid */
  if (ip_hdr->ip_p != ip_protocol_icmp)
    return 1;

  /* Ensure ICMP header has correct checksum */
  icmp_received_sum = icmp_hdr->icmp_sum;
  icmp_hdr->icmp_sum = 0;

  if (cksum(icmp_hdr, ntohs(ip_hdr->ip_len) - ip_hdr->ip_hl * 4) != icmp_received_sum) {
    printf("ICMP header does not pass checksum check\n");
    return 0;
  }

  icmp_hdr->icmp_sum = icmp_received_sum;

  return 1;
}

/*---------------------------------------------------------------------
 * Method: sr_ip_recompute_checksum(sr_ip_hdr_t *ip_hdr)
 * Scope:  Global
 *
 * Check if the IP packet meet the minimum length, and verify the checksum
 * of the IP header and ICMP ip header, if IP packet fails sanity check,
 * it will be dropped
 *
 *---------------------------------------------------------------------*/

void sr_ip_recompute_checksum(sr_ip_hdr_t *ip_hdr)
{
  uint16_t ip_recomputed_sum;

  ip_hdr->ip_sum = 0;

  ip_recomputed_sum = cksum(ip_hdr, ip_hdr->ip_hl * 4);

  ip_hdr->ip_sum = ip_recomputed_sum;
}

/*---------------------------------------------------------------------
 * Method: sr_longest_prefix_match(struct sr_instance* sr, uint32_t ip)
 * Scope:  Global
 *
 *
 *---------------------------------------------------------------------*/

struct sr_rt* sr_longest_prefix_match(struct sr_instance* sr, uint32_t ip)
{
  struct in_addr ip_addr;
  ip_addr.s_addr = ip;

  struct sr_rt* rt_walker;
  struct sr_rt* lpm;
  rt_walker = 0;
  lpm = 0;
  unsigned long longest_len = 0;

  if (sr->routing_table == 0) {
    printf(" *warning* Routing table empty \n");
    return lpm;
  }

  rt_walker = sr->routing_table;

  /* Iterate through routing table and find longest prefix match */
  while(rt_walker) {
    if ((rt_walker->dest.s_addr & rt_walker->mask.s_addr) == (ip_addr.s_addr & rt_walker->mask.s_addr) && longest_len <= rt_walker->mask.s_addr) {
      longest_len = rt_walker->mask.s_addr;
      lpm = rt_walker;
    }
    rt_walker = rt_walker->next;
  }

  return lpm;
}

/*---------------------------------------------------------------------
 * Method: sr_add_ethernet_header_and_send_packet()
 * Scope:  Global
 *
 *
 *---------------------------------------------------------------------*/

void sr_add_ethernet_header_and_send_packet(struct sr_instance *sr,
        uint32_t target_ip,
        uint8_t *receiver_mac,
        uint8_t *packet,
        unsigned int len,
        uint16_t ether_type)
{
  struct sr_rt *entry = sr_longest_prefix_match(sr, target_ip);
  unsigned int packet_len = len + sizeof(sr_ethernet_hdr_t);
  uint8_t *buf = malloc(packet_len);
  struct sr_ethernet_hdr *ethernet_hdr = malloc(sizeof(sr_ethernet_hdr_t));
  struct sr_if *iface = sr_get_interface(sr, entry->interface);

  /* Contruct Ethernet header */
  ethernet_hdr->ether_type = ether_type;
  memcpy(ethernet_hdr->ether_dhost, receiver_mac, ETHER_ADDR_LEN);
  memcpy(ethernet_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);

  /* Add Ethernet header to the packet */
  memcpy(buf, ethernet_hdr, sizeof(sr_ethernet_hdr_t));
  memcpy(buf + sizeof(sr_ethernet_hdr_t), packet, len);

  /* Send the packet */
  sr_send_packet(sr, buf, len + sizeof(sr_ethernet_hdr_t), entry->interface);
  /* Return memory back to os */
  free(buf);
  free(ethernet_hdr);
}

/*---------------------------------------------------------------------
 * Method: sr_send_arp_reply(struct sr_instance* sr, uint8_t *packet, char * interface)
 * Scope:  Global
 *
 * This method takes an ARP packet which is an APR request and send an
 * ARP reply back to the source who is asking for next-hop MAC address.
 *
 *---------------------------------------------------------------------*/
void sr_send_arp_reply(struct sr_instance* sr, uint8_t *packet, char* interface)
{
  sr_ethernet_hdr_t *ethernet_hdr = (sr_ethernet_hdr_t *)packet;
  sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

  struct sr_if *iface = sr_get_interface(sr, interface);

  /* Construct ARP header */
  sr_arp_hdr_t *arp_reply_hdr = malloc(sizeof(sr_arp_hdr_t));

  memcpy(arp_reply_hdr, arp_hdr, sizeof(sr_arp_hdr_t));
  arp_reply_hdr->ar_op = htons(arp_op_reply);
  arp_reply_hdr->ar_sip = arp_hdr->ar_tip;
  arp_reply_hdr->ar_tip = arp_hdr->ar_sip;
  memcpy(arp_reply_hdr->ar_sha, iface->addr, ETHER_ADDR_LEN);
  memcpy(arp_reply_hdr->ar_tha, ethernet_hdr->ether_shost, ETHER_ADDR_LEN);

  sr_add_ethernet_header_and_send_packet(sr, arp_hdr->ar_sip, ethernet_hdr->ether_shost, (uint8_t *)arp_reply_hdr,
                                             sizeof(sr_arp_hdr_t), htons(ethertype_arp));
  free(arp_reply_hdr);
}

/*---------------------------------------------------------------------
 * Method: sr_send_arp_request(struct sr_instance* sr, uint8_t *packet)
 * Scope:  Global
 *
 * This method takes an IP packet and send a broadcast ARP request for
 * the next-hop MAC address.
 *
 *---------------------------------------------------------------------*/
void sr_send_arp_request(struct sr_instance* sr, uint8_t *packet)
{
  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  /* Look up the interface with the destination ip */
  struct sr_rt *entry = sr_longest_prefix_match(sr, ip_hdr->ip_dst);
  struct sr_if *iface = sr_get_interface(sr, entry->interface);

  /* Construct ARP header */
  sr_arp_hdr_t *arp_hdr = malloc(sizeof(sr_arp_hdr_t));
  arp_hdr->ar_op = htons(arp_op_request);
  arp_hdr->ar_sip = iface->ip;
  arp_hdr->ar_tip = ip_hdr->ip_dst;
  arp_hdr->ar_hrd = htons(arp_hrd_ethernet);
  arp_hdr->ar_pro = htons(ethertype_ip);
  arp_hdr->ar_hln = ETHER_ADDR_LEN;
  arp_hdr->ar_pln = sizeof(uint32_t);
  memcpy(&(arp_hdr->ar_sha), iface->addr, ETHER_ADDR_LEN);

  /* Add broadcast MAC address - FF:FF:FF:FF:FF:FF */
  int i;
  unsigned char broadcast[ETHER_ADDR_LEN];
  for (i = 0; i < ETHER_ADDR_LEN; ++i) {
    broadcast[i] = 0xFF;
  }
  memcpy(&(arp_hdr->ar_tha), broadcast, ETHER_ADDR_LEN);

  /* Send ARP request */
  sr_add_ethernet_header_and_send_packet(sr, ip_hdr->ip_dst, (uint8_t *)broadcast, (uint8_t *)arp_hdr,
                                             sizeof(sr_arp_hdr_t), htons(ethertype_arp));
  free(arp_hdr);
}

/*---------------------------------------------------------------------
 * Method: sr_process_arp_reply(struct sr_instance* sr, uint8_t *packet)
 * Scope:  Global
 *
 * Takes the IP-MAC mapping ARP reply packet and cache it,  go through 
 * ARP request queue and send any outstanding packets.
 *
 *---------------------------------------------------------------------*/
void sr_process_arp_reply(struct sr_instance* sr, uint8_t *packet)
{
  sr_ethernet_hdr_t *ethernet_hdr = (sr_ethernet_hdr_t *)packet;
  sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

  struct sr_arpreq *req = sr_arpcache_insert(&sr->cache, (unsigned char*)ethernet_hdr->ether_shost, arp_hdr->ar_sip);

  if (req) {
    /* Send all packets on the req->packets linked list, */
    while (req->packets) {
      /* Change the packet MAC address to destination MAC address and forward it */
      sr_ethernet_hdr_t *packet_ether_hdr = (sr_ethernet_hdr_t *)req->packets->buf;
      sr_ip_hdr_t *packet_ip_hdr = (sr_ip_hdr_t *)(req->packets->buf + sizeof(sr_ethernet_hdr_t));

      memcpy(packet_ether_hdr->ether_dhost, ethernet_hdr->ether_shost, ETHER_ADDR_LEN);

      /* Get the interface and change ethernet source address */
      struct sr_rt *entry = sr_longest_prefix_match(sr, packet_ip_hdr->ip_dst);
      struct sr_if *iface = sr_get_interface(sr, entry->interface);
      memcpy(packet_ether_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);

      sr_send_packet(sr, req->packets->buf, req->packets->len, iface->name);
      req->packets = req->packets->next;
    }
    sr_arpreq_destroy(&(sr->cache), req);
  }
}

/*---------------------------------------------------------------------
 * Method: sr_send_icmp(sr, packet, type, code, icmp_len)
 * Scope:  Global
 *
 * Send an ICMP message of type 3 or type 11
 * - Destination net unreachable (type 3, code 0)
 * - Destination host unreachable (type 3, code 1)
 * - Port unreachable (type 3, code 3)
 * - Time exceeded (type 11, code 0)
 *
 *---------------------------------------------------------------------*/

void sr_send_icmp(struct sr_instance* sr, uint8_t *packet, uint8_t type, uint8_t code)
{
  unsigned int eth_len = sizeof(sr_ethernet_hdr_t), ip_len = sizeof(sr_ip_hdr_t), icmp_len = sizeof(sr_icmp_t3_hdr_t);
  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + eth_len);

  unsigned int len = ip_len + icmp_len;
  uint8_t *icmp_packet = malloc(len);
  sr_ip_hdr_t *icmp_ip_hdr;
  icmp_ip_hdr = (sr_ip_hdr_t *)icmp_packet;

  /* Get source interface */
  struct sr_rt *entry = sr_longest_prefix_match(sr, ip_hdr->ip_src);
  struct sr_if *iface = sr_get_interface(sr, entry->interface);

  /* Construct IP header */
  icmp_ip_hdr->ip_v = 4;
  icmp_ip_hdr->ip_hl = ip_len / 4;
  icmp_ip_hdr->ip_tos = 0;
  icmp_ip_hdr->ip_len = htons(len);
  icmp_ip_hdr->ip_id = ip_hdr->ip_id;
  icmp_ip_hdr->ip_off = htons(IP_DF);
  icmp_ip_hdr->ip_ttl = 64;
  icmp_ip_hdr->ip_p = ip_protocol_icmp;
  if (code == ICMP_PORT_CODE)
    icmp_ip_hdr->ip_src = ip_hdr->ip_dst;
  else
    icmp_ip_hdr->ip_src = iface->ip;
  icmp_ip_hdr->ip_dst = ip_hdr->ip_src;
  icmp_ip_hdr->ip_sum = 0;

  /* Compute and set IP checksum */
  icmp_ip_hdr->ip_sum = cksum(icmp_ip_hdr, ip_len);

  /* Construct ICMP header */
  sr_icmp_t3_hdr_t *new_icmp_hdr;
  new_icmp_hdr = (sr_icmp_t3_hdr_t *)(icmp_packet + ip_len);

  new_icmp_hdr->icmp_type = type;
  new_icmp_hdr->icmp_code = code;
  new_icmp_hdr->unused = 0;
  new_icmp_hdr->next_mtu = 0;
  memcpy(new_icmp_hdr->data, ip_hdr, ICMP_DATA_SIZE);

  /* Compute and set ICMP checksum */
  new_icmp_hdr->icmp_sum = 0;
  new_icmp_hdr->icmp_sum = cksum(new_icmp_hdr, icmp_len);

  /*sr_add_ethernet_header_and_send_packet(sr, ip_hdr->ip_src, ethernet_hdr->ether_shost, icmp_packet, len, htons(ethertype_ip));*/

  /* Add Ethernet header */
  unsigned int packet_len = len + eth_len;
  uint8_t *buf = malloc(packet_len);
  struct sr_ethernet_hdr *icmp_eth_hdr = malloc(eth_len);

  icmp_eth_hdr->ether_type = htons(ethertype_ip);
  /*memcpy(icmp_eth_hdr->ether_dhost, ethernet_hdr->ether_shost, ETHER_ADDR_LEN);*/
  memcpy(icmp_eth_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);


  memcpy(buf, icmp_eth_hdr, eth_len);
  memcpy(buf + eth_len, icmp_packet, len);
  sr_forward_ip_packet(sr, buf, len + eth_len, entry->interface);
  free(icmp_packet);
}

/*---------------------------------------------------------------------
 * Method: sr_send_icmp_echo_reply(struct sr_instance* sr, uint8_t* packet, unsigned int len, char* interface)
 * Scope:  Global
 *
 * Takes the ICMP Echo request packet and send ICMP Echo reply back
 *
 *---------------------------------------------------------------------*/
void sr_send_icmp_echo_reply(struct sr_instance* sr, uint8_t* packet, unsigned int len, char* interface)
{
  sr_ethernet_hdr_t *ethernet_hdr = (sr_ethernet_hdr_t *)packet;

  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) +\
                                                       sizeof(sr_ip_hdr_t));

  /* Modify Ethernet header */
  struct sr_if* iface = sr_get_interface(sr, interface);
  memcpy(ethernet_hdr->ether_dhost, ethernet_hdr->ether_shost, ETHER_ADDR_LEN);
  memcpy(ethernet_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);

  /* Modify IP header */
  ip_hdr->ip_dst = ip_hdr->ip_src;
  ip_hdr->ip_src = iface->ip;
  ip_hdr->ip_sum = 0;
  ip_hdr->ip_sum = cksum(ip_hdr, ip_hdr->ip_hl * 4);

  /* Modify ICMP header */
  icmp_hdr->icmp_type = ICMP_ECHO_REPLY_TYPE;
  icmp_hdr->icmp_sum = 0;
  icmp_hdr->icmp_sum = cksum(icmp_hdr, ntohs(ip_hdr->ip_len) - (ip_hdr->ip_hl * 4));

  sr_send_packet(sr, packet, len, interface);
}

