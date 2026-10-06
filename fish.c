#include "fish.h"
#include <assert.h>
#include <signal.h>
#include <string.h>
#include "smartalloc.h"
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>


#define L2_IMPL
 
static int noprompt = 0;

struct l2_header {
    fn_l2addr_t dst;
    fn_l2addr_t src;
    uint16_t checksum;
    uint16_t length;
    uint8_t l3_protocol;
} __attribute__((packed));

struct arp_header {
    uint32_t query_type;
    fnaddr_t queried_l3_addr;
    fn_l2addr_t queried_l2_addr;
} __attribute__((packed));

void sigint_handler(int sig)
{
   if (SIGINT == sig)
	   fish_main_exit();
}

static int print_route(void *callback_data __attribute__((unused)),
      fnaddr_t dest, int prefix_len __attribute((unused)),
      fnaddr_t net_hop __attribute((unused)),
      int metric __attribute((unused)),
      void *entry_data __attribute__((unused))) {
   printf("%s\n", fn_ntoa(dest));
   return 0;
}

static void keyboard_callback(char *line)
{
   if (0 == strcasecmp("show neighbors", line))
      fish_print_neighbor_table();
   else if (0 == strcasecmp("show arp", line))
      fish_print_arp_table();
   else if (0 == strcasecmp("show route", line)) {
      fish_print_forwarding_table();
      fish_fwd.iterate_entries(&print_route, NULL, FISH_FWD_TYPE_BROADCAST);
   }
   else if (0 == strcasecmp("show dv", line))
      fish_print_dv_state();
   else if (0 == strcasecmp("quit", line) || 0 == strcasecmp("exit", line))
      fish_main_exit();
   else if (0 == strcasecmp("show topo", line))
      fish_print_lsa_topo();
   else if (0 == strcasecmp("help", line) || 0 == strcasecmp("?", line)) {
      printf("Available commands are:\n"
             "    exit                         Quit the fishnode\n"
             "    help                         Display this message\n"
             "    quit                         Quit the fishnode\n"
             "    show arp                     Display the ARP table\n"
             "    show dv                      Display the dv routing state\n"
             "    show neighbors               Display the neighbor table\n"
             "    show route                   Display the forwarding table\n"
             "    show topo                    Display the link-state routing\n"
             "                                 algorithm's view of the network\n"
             "                                 topology\n"
             "    ?                            Display this message\n"
            );
   }
   else if (line[0] != 0)
      printf("Type 'help' or '?' for a list of available commands.  "
             "Unknown command: %s\n", line);

   if (!noprompt)
      printf("> ");

   fflush(stdout);
}

// Prototypes for program 2.  Taken directly from fish.h header file
#ifdef L2_IMPL

void my_arp_resolution_cb(fn_l2addr_t addr, void *param) {
   struct l2_header *capped = (struct l2_header*) param;
   capped->dst = addr;
   capped->checksum = in_cksum(capped, ntohs(capped->length));
   fish_l1_send(capped);
   free(capped);
   return;
}

int my_fish_l2_send(void *l3frame, fnaddr_t next_hop, int len, uint8_t l2_proto)
{
   struct l2_header *capped = (struct l2_header*) malloc(len + sizeof(struct l2_header));
   if (capped == NULL) {
      return -1;
   }
   capped->src = fish_getl2address();
   capped->checksum = 0;
   capped->length = htons(len + sizeof(struct l2_header));
   capped->l3_protocol = l2_proto;
   
   memcpy(capped + 1, l3frame, len);
   fish_arp.resolve_fnaddr(next_hop, my_arp_resolution_cb, capped);
   return 0;
}

int my_fishnode_l2_receive(void *l2frame)
{
   struct l2_header cap;
   memcpy(&cap, l2frame, sizeof(cap));

   uint16_t total_length = ntohs(cap.length);
   
   unsigned short corrupted = in_cksum(l2frame, total_length);
   if (corrupted) {
      return 0;
   }

   fn_l2addr_t my_address = fish_getl2address();

   if (FNL2_EQ(cap.dst, my_address) || FNL2_EQ(cap.dst, ALL_L2_NEIGHBORS)) {
      if (cap.l3_protocol == 0x02) {
         fish_arp.arp_received(l2frame);
         return 0;
      }
      fish_l3.fish_l3_receive(l2frame+sizeof(cap), total_length-sizeof(cap), cap.l3_protocol);
   }
   return 0;
}

void my_arp_received(void *l2frame)
{
   struct l2_header l2_cap;
   struct arp_header l3_cap;
   
   struct l2_header *l2frame_cap = (struct l2_header *) calloc(1, sizeof(l2_cap) + sizeof(l3_cap));
   if (l2frame_cap == NULL) {
      return;
   }

   memcpy(&l2_cap, l2frame, sizeof(l2_cap));
   memcpy(&l3_cap, l2frame+sizeof(l2_cap), sizeof(l3_cap));
   memcpy(l2frame_cap, l2frame, sizeof(l2_cap) + sizeof(l3_cap));
   uint32_t type = ntohl(l3_cap.query_type);
   if (type == 0x01) {
      /* ARP Request */
      uint32_t my_ip = fish_getaddress();
      uint32_t query_ip = l3_cap.queried_l3_addr;

      if (my_ip == query_ip) {
        l2frame_cap->dst = l2_cap.src;
        l2frame_cap->src = fish_getl2address();
        l2frame_cap->checksum = 0;
        struct arp_header *arpframe = (struct arp_header *) (l2frame_cap+1);
        arpframe->query_type = htonl(0x02);
        arpframe->queried_l2_addr = fish_getl2address();
        l2frame_cap->checksum = in_cksum(l2frame_cap, sizeof(l2_cap)+sizeof(l3_cap));
        fish_l1_send(l2frame_cap);
      } 
   } else if (type == 0x02) {
        fish_arp.add_arp_entry(l3_cap.queried_l2_addr, l3_cap.queried_l3_addr, 180);
   }
   free(l2frame_cap);
   return;
}

void my_send_arp_request(fnaddr_t l3addr)
{
    char frame[sizeof(struct l2_header) + sizeof(struct arp_header)];

    struct l2_header *l2_cap = (struct l2_header *) frame;
    struct arp_header *arp_cap = (struct arp_header *) (l2_cap + 1);

    l2_cap->dst = ALL_L2_NEIGHBORS;
    l2_cap->src = fish_getl2address();
    l2_cap->checksum = 0;
    l2_cap->length = htons(sizeof(struct l2_header) + sizeof(struct arp_header));
    l2_cap->l3_protocol = 2;
    
    arp_cap->query_type = htonl(1);
    arp_cap->queried_l3_addr = l3addr;
    
    l2_cap->checksum = in_cksum(frame, sizeof(struct l2_header) + sizeof(struct arp_header));
    fish_l1_send(frame);
    return;
}

void my_add_arp_entry(fn_l2addr_t l2addr, fnaddr_t addr, int timeout)
{
}

void my_resolve_fnaddr(fnaddr_t addr, arp_resolution_cb cb, void *param)
{
}
#endif

#ifdef L3_IMPL
int my_fishnode_l3_receive(void *l3frame, int len)
{
   return 0;
}

int my_fish_l3_send(void *l4frame, int len, fnaddr_t dst_addr,
               uint8_t proto, uint8_t ttl)
{
   return 0;
}

int my_fish_l3_forward(void *l3frame, int len)
{
   return 0;
}

// Callback to broadcast DV advertisement
void my_timed_event(void*)
{
}

// Full functionality
void* my_add_fwtable_entry(fnaddr_t dst, int prefix_length, fnaddr_t next_hop,
                   int metric, char type, void *user_data)
{
   return NULL;
}

void* my_remove_fwtable_entry(void *route_key)
{
   return NULL;
}

int my_update_fwtable_metric(void *route_key, int new_metric)
{
   return 0;
}

fnaddr_t my_longest_prefix_match(fnaddr_t addr)
{
   return 0;
}
#endif

int main(int argc, char **argv)
{
	struct sigaction sa;
   int arg_offset = 1;

   /* Verify and parse the command line parameters */
	if (argc != 2 && argc != 3 && argc != 4)
	{
		printf("Usage: %s [-noprompt] <fishhead address> [<fn address>]\n", argv[0]);
		return 1;
	}

   if (0 == strcasecmp(argv[arg_offset], "-noprompt")) {
      noprompt = 1;
      arg_offset++;
   }

   /* Install the signal handler */
	sa.sa_handler = sigint_handler;
	sigfillset(&sa.sa_mask);
	sa.sa_flags = 0;
	if (-1 == sigaction(SIGINT, &sa, NULL))
	{
		perror("Couldn't set signal handler for SIGINT");
		return 2;
	}

   /* Set up debugging output */
#ifdef DEBUG
	fish_setdebuglevel(FISH_DEBUG_INTERNAL);
	// fish_setdebuglevel(FISH_DEBUG_ALL);
#else
	fish_setdebuglevel(FISH_DEBUG_NONE);
#endif
	fish_setdebugfile(stdout);

   /* Join the fishnet */
	if (argc-arg_offset == 1)
		fish_joinnetwork(argv[arg_offset]);
	else
		fish_joinnetwork_addr(argv[arg_offset], fn_aton(argv[arg_offset+1]));

   /* Install the command line parsing callback */
   fish_keybhook(keyboard_callback);
   if (!noprompt)
      printf("> ");
   fflush(stdout);

#ifdef L2_IMPL
   // Examples of overriding function pointers for program 2 base functionality
   fish_l2.fishnode_l2_receive = &my_fishnode_l2_receive;
   fish_l2.fish_l2_send = &my_fish_l2_send;
   fish_arp.arp_received = &my_arp_received;
   fish_arp.send_arp_request = &my_send_arp_request;
   // Full functionality functions
   //fish_arp.add_arp_entry = &my_add_arp_entry;
   //fish_arp.resolve_fnaddr = &my_resolve_fnaddr;
#endif

#ifdef L3_IMPL
/*
   fish_l3.fishnode_l3_receive = &my_fishnode_l3_receive;
   fish_l3.fish_l3_send = &my_fish_l3_send;
   fish_l3.fish_l3_forward = &my_fish_l3_forward;
   // Set up a callback to broadcast DV advertisement
   fish_scheduleevent(0, &my_timed_event, NULL);
   // Full functionality
   fish_scheduleevent(0, &my_timed_event, NULL);
   // Full functionality
   fish_fwd.add_fwtable_entry = &my_add_fwtable_entry;
   fish_fwd.remove_fwtable_entry = &my_remove_fwtable_entry;
   fish_fwd.update_fwtable_metric = &my_update_fwtable_metric;
   fish_fwd.longest_prefix_match = &my_longest_prefix_match;*/
#endif

#if 1
   /* Enable the built-in neighbor protocol implementation.  This will discover
    * one-hop routes in your fishnet.  The link-state routing protocol requires
    * the neighbor protocol to be working, whereas it is redundant with DV.
    * Running them both doesn't break the fishnode, but will cause extra routing
    * overhead */
   fish_enable_neighbor_builtin( 0
         | NEIGHBOR_USE_LIBFISH_NEIGHBOR_DOWN
      );
#endif

   /* Enable the link-state routing protocol.  This requires the neighbor
    * protocol to be enabled. */
   // fish_enable_lsarouting_builtin(0);

#if 0
   /* Full-featured DV routing.  I suggest NOT using this until you have some
    * reasonable expectation that your code works.  This generates a lot of
    * routing traffic in fishnet */

   fish_enable_dvrouting_builtin( 0
         | DVROUTING_WITHDRAW_ROUTES
         | DVROUTING_TRIGGERED_UPDATES
         | RVROUTING_USE_LIBFISH_NEIGHBOR_DOWN
         | DVROUTING_SPLIT_HOR_POISON_REV
         | DVROUTING_KEEP_ROUTE_HISTORY
    );
#endif

   /* Execute the libfish event loop */
	fish_main();

   /* Clean up and exit */
   if (!noprompt)
      printf("\n");
   fish_keybhook(NULL);

	printf("Fishnode exiting cleanly.\n");

   fishnet_cleanup();

   // Cleanup your data structures here
   return 0;
}
