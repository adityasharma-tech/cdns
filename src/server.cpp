#include <arpa/inet.h>
#include <bitset>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#define MAXLINE 1024
#define PORT 5349

struct dns_hf {
  bool qr;
  uint8_t opcode;
  bool aa;
  bool tc;
  bool rd;
  bool ra;
  uint8_t z;
  uint8_t rcode;
};

struct dns_h {
  uint16_t id;
  struct dns_hf flags;
  uint16_t qdcount;
  uint16_t ancount;
  uint16_t nscount;
  uint16_t arcount;
};

struct dns_q {
  uint16_t qname;
  uint16_t qtype;
  uint16_t qclass;
};

uint16_t read_offset(const unsigned char *buffer, size_t offset) {
  return ((static_cast<uint16_t>(buffer[offset]) << 8) |
          (static_cast<uint16_t>(buffer[offset + 1])));
}

struct dns_h parse_headers(const unsigned char *buffer) {
  uint16_t id = read_offset(buffer, 0);
  uint16_t flags = read_offset(buffer, 2);

  bool qr = (flags >> 15) & 1;
  uint8_t opcode = (flags >> 11) & 0b00001111;
  bool aa = (flags >> 10) & 0b00000001;
  bool tc = (flags >> 9) & 0b00000001;
  bool rd = (flags >> 8) & 0b00000001;
  bool ra = (flags >> 7) & 0b00000001;

  uint8_t z = (flags >> 4) & 0b00000111;
  uint8_t rcode = static_cast<uint8_t>(flags) & 0b00001111;

  uint16_t qdcount = read_offset(buffer, 4);
  uint16_t ancount = read_offset(buffer, 6);
  uint16_t nscount = read_offset(buffer, 8);
  uint16_t arcount = read_offset(buffer, 10);

  std::cout << "flags:  " << std::bitset<16>(flags).to_string().c_str() << '\n';
  std::cout << "QR:     " << qr << '\n';
  std::cout << "OPCODE: " << std::bitset<4>(opcode).to_string().c_str() << '\n';
  std::cout << "AA:     " << std::bitset<1>(aa).to_string().c_str() << '\n';
  std::cout << "TC:     " << std::bitset<1>(tc).to_string().c_str() << '\n';
  std::cout << "RD:     " << std::bitset<1>(rd).to_string().c_str() << '\n';
  std::cout << "RA:     " << std::bitset<1>(ra).to_string().c_str() << '\n';
  std::cout << "Z:      " << std::bitset<3>(z).to_string().c_str() << '\n';
  std::cout << "RCODE:  " << std::bitset<4>(rcode).to_string().c_str() << '\n';

  struct dns_hf dns_flags;
  dns_flags.qr = qr;
  dns_flags.opcode = opcode;
  dns_flags.aa = aa;
  dns_flags.tc = tc;
  dns_flags.rd = rd;
  dns_flags.ra = ra;
  dns_flags.z = z;
  dns_flags.rcode = rcode;

  struct dns_h dnheader;
  dnheader.ancount = ancount;
  dnheader.arcount = arcount;
  dnheader.id = id;
  dnheader.qdcount = qdcount;
  dnheader.nscount = nscount;
  dnheader.flags = dns_flags;

  return dnheader;
}

struct dns_q parse_dnsq(const unsigned char *buffer) {
  char domain[1024];
  int b2read;
  b2read = static_cast<int>(buffer[12]);

  int i = 1;
  int idx = 0;
  while (true) {
    if (i <= b2read) {
      char b = static_cast<char>(buffer[12 + idx + 1]);
      domain[idx] = b;
    }
    i++;
    idx++;
    if (i > b2read) {
      b2read = static_cast<int>(buffer[12 + idx + 1]);
      if(b2read == 0){
          domain[idx] = '\0';
          break;
      }
      domain[idx] = '.';
      idx++;
      i = 1;
    }
  }

  std::cout << "domain name: " << domain << std::endl;

  uint16_t qtype = read_offset(buffer, 14);
  uint16_t qclass = read_offset(buffer, 16);

  struct dns_q dnsq;
  // dnsq.qname = qname;
  // dnsq.qclass = qclass;
  // dnsq.qtype = qtype;

  // std::cout << "QNAME:  " << std::bitset<16>(qname).to_string().c_str() <<
  // '\n'; std::cout << "QCLASS:  " <<
  // std::bitset<16>(qclass).to_string().c_str() << '\n'; std::cout << "QTYPE:
  // " << std::bitset<16>(qtype).to_string().c_str() << '\n';

  return dnsq;
}

int main() {
  unsigned char buffer[MAXLINE];
  struct sockaddr_in servaddr, clientaddr;

  int sockfd = socket(AF_INET, SOCK_DGRAM, 0);

  if (sockfd < 0) {
    perror("failed to create socket");
    exit(EXIT_FAILURE);
  }

  memset(&servaddr, 0, sizeof(servaddr));
  memset(&clientaddr, 0, sizeof(clientaddr));

  servaddr.sin_addr.s_addr = inet_addr("127.0.0.1");
  servaddr.sin_port = htons(PORT);
  servaddr.sin_family = AF_INET;

  socklen_t len = sizeof(servaddr);
  if (bind(sockfd, (const struct sockaddr *)&servaddr, len) < 0) {
    perror("failed to bind socket to port");
    close(sockfd);
    exit(EXIT_FAILURE);
  }

  socklen_t cllen = sizeof(clientaddr);

  while (true) {
    int n = recvfrom(sockfd, buffer, MAXLINE, 0, (struct sockaddr *)&clientaddr,
                     (socklen_t *)&cllen);
    if (n < 0) {
      perror("recvfrom failed");
      close(sockfd);
      exit(EXIT_FAILURE);
    }

    buffer[n] = '\0';

    std::cout << "Received " << n << " bytes\n";

    parse_headers(buffer);
    parse_dnsq(buffer);

    printf("\n");
    memset(&buffer, 0, MAXLINE);
  }

  close(sockfd);

  return 0;
}
