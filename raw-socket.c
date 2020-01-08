#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <arpa/inet.h> // IPPROTO_TCP
#include <errno.h>
#include <string.h>

int main(int argc, char** argv) {
  struct sockaddr_in source_socket_address, dest_socket_address;
  unsigned char* buffer = (unsigned char*) malloc(65536);
  int sock = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);

  if (sock < 0) {
    printf("Could not get socket option. Error was %s\n", strerror(errno));
  }
  printf("created raw socket....\n");

  while(1) {
    int packet_size = recvfrom(sock, buffer ,65536 ,0 ,NULL,NULL);
    if (packet_size == -1) {
      printf("Failed to get packets\n");
      return 1;
    }

    struct iphdr* ip_packet = (struct iphdr*) buffer;

    memset(&source_socket_address, 0, sizeof(source_socket_address));
    source_socket_address.sin_addr.s_addr = ip_packet->saddr;
    memset(&dest_socket_address, 0, sizeof(dest_socket_address));
    dest_socket_address.sin_addr.s_addr = ip_packet->daddr;

    printf("Incoming Packet: \n");
    printf("Packet Size (bytes): %d\n", ntohs(ip_packet->tot_len));
    printf("Source Address: %s\n", (char*) inet_ntoa(source_socket_address.sin_addr));
    printf("Destination Address: %s\n", (char*) inet_ntoa(dest_socket_address.sin_addr));
    printf("Identification: %d\n\n", ntohs(ip_packet->id));
  }

  return 0;
}
