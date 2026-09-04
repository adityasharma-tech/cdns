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
#define HEADER_SIZE 12

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
  char *qname;
  uint16_t qtype;
  uint16_t qclass;
  int length;
};

enum ans_type {
  A = 1
};

uint16_t read_offset(const unsigned char *buffer, size_t offset) {
  return ((static_cast<uint16_t>(buffer[offset]) << 8) |
          (static_cast<uint16_t>(buffer[offset + 1])));
}

void update_qr_to_response(unsigned char *buffer) {
  buffer[2] = buffer[2] | 0b10000000;
  buffer[3] = 0x0000;
}

void update_ancount(unsigned char *buffer){
    uint16_t ancount = 1;
    std::memcpy(buffer+7, &ancount, sizeof(uint16_t));
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
  std::cout << "QDCOUNT:  " << std::bitset<16>(qdcount).to_string().c_str()
            << '\n';

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
  b2read = static_cast<int>(buffer[HEADER_SIZE]);

  int i = 1;
  int idx = 0;
  while (true) {
    if (i <= b2read) {
      char b = static_cast<char>(buffer[HEADER_SIZE + idx + 1]);
      domain[idx] = b;
    }
    i++;
    idx++;
    if (i > b2read) {
      b2read = static_cast<int>(buffer[HEADER_SIZE + idx + 1]);
      if (b2read == 0) {
        domain[idx] = '\0';
        break;
      }
      domain[idx] = '.';
      idx++;
      i = 1;
    }
  }

  std::cout << "(bytes: " << idx + 1 << " ) domain name: " << domain
            << std::endl;

  uint16_t qtype = read_offset(buffer, HEADER_SIZE + idx + 2);

  struct dns_q dnsq;
  dnsq.qname = domain;
  dnsq.qtype = qtype;
  uint16_t qclass = read_offset(buffer, HEADER_SIZE + idx + 4);

  dnsq.qclass = qclass;

  std::cout << "qclass:  " << std::bitset<16>(dnsq.qclass) << '\n';
  std::cout << "qtype:" << std::bitset<16>(dnsq.qtype).to_string().c_str()
            << '\n';

  dnsq.length = idx + 6;
  return dnsq;
}

void set_ans_name_pointer(unsigned char *buffer, int *pos){
    buffer[++(*pos)] = 0b11000000;
    buffer[++(*pos)] = 0xC;
}

void set_ans_type(unsigned char *buffer, int *pos, enum ans_type type){
    uint16_t _type = htons(type);
    memcpy(buffer+(*pos)+1, &_type, sizeof(uint16_t));
}

void set_default_ans_class(unsigned char *buffer, int* pos){
    (*pos) += 2; // 15
    buffer[*pos] = 0x1; //15
}

void set_ans_ttl(unsigned char *buffer, int* pos, uint32_t ttl){
    (*pos)++; // 16
    std::memcpy(buffer+(*pos), &ttl, sizeof(uint32_t)); // 16,17,18,19
    (*pos)+=3;
}

void set_ans_rdlen(unsigned char *buffer, int* pos, uint16_t rdlen){
    (*pos)++; // 20
    std::memcpy(buffer+(*pos), &rdlen, sizeof(uint16_t));
    (*pos)+= 1;
}

void write_ans_rdata(unsigned char *buffer, int* pos, enum ans_type type){
    if(type == ans_type::A){
        buffer[++(*pos)] = 1;
        buffer[++(*pos)] = 1;
        buffer[++(*pos)] = 1;
        buffer[++(*pos)] = 1;
    } else {
        perror("we dont have support for this QUESTION TYPE");
        exit(EXIT_FAILURE);
    }
}

int attach_answer(unsigned char *buffer, int qn_len) {
    int curr_pos = HEADER_SIZE + qn_len;
    update_ancount(buffer);
    set_ans_name_pointer(buffer, &curr_pos);

    std::cout << "name in answer :" << std::bitset<16>( static_cast<uint16_t>(buffer[curr_pos] << 8) | static_cast<uint16_t>(buffer[curr_pos+1])).to_string().c_str()<< '\n';

    set_ans_type(buffer, &curr_pos, ans_type::A);
    set_default_ans_class(buffer, &curr_pos);
    set_ans_ttl(buffer, &curr_pos, 300);
    set_ans_rdlen(buffer, &curr_pos, 4);

    char rdata[4];
    write_ans_rdata(buffer, &curr_pos, ans_type::A);
    return curr_pos;
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
    dns_q question = parse_dnsq(buffer);
    update_qr_to_response(buffer);
    int buff_size = attach_answer(buffer, question.length);

    int sn = sendto(sockfd, buffer, buff_size, 0, (const struct sockaddr *)&clientaddr, sizeof(clientaddr));

    if(n < 0){
        perror("sendto failed");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    printf("\n");
    memset(&buffer, 0, MAXLINE);
  }

  close(sockfd);

  return 0;
}
