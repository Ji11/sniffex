#define _DEFAULT_SOURCE

#include <sys/types.h>
#include <pcap.h>
#include <mysql/mysql.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <limits.h>

#define SNAP_LEN 65535
#define SIZE_ETHERNET 14
#define ETHER_ADDR_LEN 6
#define FILTER_EXP "tcp src port 80"
#define TARGET_PACKET_COUNT 10
#define PAYLOAD_LOG_RELATIVE_PATH "data/payload.log"
#define DEFAULT_DB_HOST "127.0.0.1"
#define DEFAULT_DB_USER "root"
#define DEFAULT_DB_PASS "123456"
#define DEFAULT_DB_NAME "packet_capture"
#define DEFAULT_DB_PORT 3306

struct sniff_ethernet
{
    u_char ether_dhost[ETHER_ADDR_LEN];
    u_char ether_shost[ETHER_ADDR_LEN];
    u_short ether_type;
};

struct sniff_ip
{
    u_char ip_vhl;
    u_char ip_tos;
    u_short ip_len;
    u_short ip_id;
    u_short ip_off;
#define IP_RF 0x8000
#define IP_DF 0x4000
#define IP_MF 0x2000
#define IP_OFFMASK 0x1fff
    u_char ip_ttl;
    u_char ip_p;
    u_short ip_sum;
    struct in_addr ip_src, ip_dst;
};

#define IP_HL(ip) (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip) (((ip)->ip_vhl) >> 4)

typedef u_int tcp_seq;

struct sniff_tcp
{
    u_short th_sport;
    u_short th_dport;
    tcp_seq th_seq;
    tcp_seq th_ack;
    u_char th_offx2;
#define TH_OFF(th) (((th)->th_offx2 & 0xf0) >> 4)
    u_char th_flags;
    u_short th_win;
    u_short th_sum;
    u_short th_urp;
};

struct packet_record
{
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    unsigned int src_port;
    unsigned int dst_port;
    char content_type[128];
    unsigned int payload_size;
};

struct app_state
{
    pcap_t *handle;
    MYSQL *db;
    FILE *payload_fp;
    char payload_file_path[PATH_MAX];
    unsigned int qualified_count;
};

static void print_app_usage(void);
static void print_hex_ascii_line(FILE *out, const u_char *payload, int len, int offset);
static void print_payload(FILE *out, const u_char *payload, int len);
static const u_char *find_bytes(const u_char *haystack, size_t haystack_len, const char *needle, size_t needle_len);
static int extract_content_type(const u_char *payload, int len, char *content_type, size_t content_type_size);
static int is_allowed_content_type(const char *content_type);
static int parse_packet_record(const struct pcap_pkthdr *header, const u_char *packet, struct packet_record *record, const u_char **payload_ptr);
static int append_payload_block(FILE *fp, unsigned int packet_number, unsigned long long feature_id, const struct packet_record *record, const u_char *payload, unsigned long long *file_offset_out);
static int rewind_payload_log(FILE *fp, unsigned long long file_offset);
static unsigned long long insert_feature(MYSQL *db, const struct packet_record *record);
static int insert_payload(MYSQL *db, unsigned long long feature_id, const char *file_path, unsigned long long file_offset, const char *data_type);
static MYSQL *open_database(void);
static int ensure_data_directory(void);
static int build_payload_log_path(char *buffer, size_t buffer_size);
static int lookup_default_device(char *buffer, size_t buffer_size, char *errbuf);
static void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

static void print_app_usage(void)
{
    printf("Usage: %s [interface]\n", "sniffex");
    printf("\n");
    printf("Options:\n");
    printf("    interface    Listen on <interface> for packets.\n");
    printf("\n");
    return;
}

/*
 * print data in rows of 16 bytes: offset   hex   ascii
 * 00000   47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a   GET / HTTP/1.1..
 */
static void print_hex_ascii_line(FILE *out, const u_char *payload, int len, int offset)
{
    int i;
    int gap;
    const u_char *ch;

    fprintf(out, "%05d   ", offset);

    ch = payload;
    for (i = 0; i < len; i++)
    {
        fprintf(out, "%02x ", *ch);
        ch++;
        if (i == 7)
        {
            fprintf(out, " ");
        }
    }

    if (len < 8)
    {
        fprintf(out, " ");
    }

    if (len < 16)
    {
        gap = 16 - len;
        for (i = 0; i < gap; i++)
        {
            fprintf(out, "   ");
        }
    }

    fprintf(out, "   ");

    ch = payload;
    for (i = 0; i < len; i++)
    {
        fprintf(out, "%c", isprint(*ch) ? *ch : '.');
        ch++;
    }

    fprintf(out, "\n");
}

static void print_payload(FILE *out, const u_char *payload, int len)
{
    int len_rem = len;
    int line_width = 16;
    int line_len;
    int offset = 0;
    const u_char *ch = payload;

    if (len <= 0)
    {
        return;
    }

    while (len_rem > 0)
    {
        line_len = len_rem < line_width ? len_rem : line_width;
        print_hex_ascii_line(out, ch, line_len, offset);
        len_rem -= line_len;
        ch += line_len;
        offset += line_len;
    }
}

// 定位到HTTP响应头的 \r\n\r\n
static const u_char *find_bytes(const u_char *haystack, size_t haystack_len, const char *needle, size_t needle_len)
{
    size_t i;

    if (needle_len == 0 || haystack_len < needle_len)
    {
        return NULL;
    }

    for (i = 0; i <= haystack_len - needle_len; i++)
    {
        if (memcmp(haystack + i, needle, needle_len) == 0)
        {
            return haystack + i;
        }
    }

    return NULL;
}

static int extract_content_type(const u_char *payload, int len, char *content_type, size_t content_type_size)
{
    const u_char *header_end;
    size_t header_len;
    char *headers;
    char *line;
    char *saveptr = NULL;

    // HTTP响应头以"HTTP/1."开头
    if (len < 7 || memcmp(payload, "HTTP/1.", 7) != 0)
    {
        return 0;
    }

    // 找到HTTP响应头的结束标记
    header_end = find_bytes(payload, (size_t)len, "\r\n\r\n", 4);
    if (header_end == NULL)
    {
        return 0;
    }

    header_len = (size_t)(header_end - payload) + 4; // 尾 - 头 + \r\n\r\n
    headers = (char *)malloc(header_len + 1);
    if (headers == NULL)
    {
        return 0;
    }

    // 把响应头部放入headers
    memcpy(headers, payload, header_len);
    headers[header_len] = '\0';

    // 按行寻找content-type
    line = strtok_r(headers, "\r\n", &saveptr);
    while (line != NULL)
    {
        if (strncasecmp(line, "Content-Type:", 13) == 0)
        {
            // 找到content-type，就截取类型
            char *value = line + 13;
            char *semicolon;
            char *end;
            size_t value_len;
            char normalized[128];
            size_t i;

            while (*value != '\0' && isspace((unsigned char)*value))
            {
                value++;
            }

            semicolon = strchr(value, ';');
            if (semicolon != NULL)
            {
                *semicolon = '\0';
            }

            end = value + strlen(value);
            while (end > value && isspace((unsigned char)*(end - 1)))
            {
                end--;
            }
            *end = '\0';

            value_len = strlen(value);
            if (value_len == 0 || value_len >= sizeof(normalized))
            {
                free(headers);
                return 0;
            }

            for (i = 0; i < value_len; i++)
            {
                normalized[i] = (char)tolower((unsigned char)value[i]);
            }
            normalized[value_len] = '\0';

            snprintf(content_type, content_type_size, "%s", normalized);
            free(headers);
            return 1;
        }

        line = strtok_r(NULL, "\r\n", &saveptr);
    }

    free(headers);
    return 0;
}

static int is_allowed_content_type(const char *content_type)
{
    return strcmp(content_type, "image/png") == 0 ||
           strcmp(content_type, "text/plain") == 0;
}

static int parse_packet_record(const struct pcap_pkthdr *header, const u_char *packet, struct packet_record *record, const u_char **payload_ptr)
{
    const struct sniff_ip *ip;
    const struct sniff_tcp *tcp;
    int size_ip;
    int size_tcp;
    int size_payload;
    size_t transport_offset;
    size_t payload_offset;
    size_t captured_payload_len;

    if (header->caplen < SIZE_ETHERNET + sizeof(struct sniff_ip))
    {
        return 0;
    }

    ip = (const struct sniff_ip *)(packet + SIZE_ETHERNET);
    if (IP_V(ip) != 4)
    {
        return 0;
    }

    size_ip = IP_HL(ip) * 4;
    if (size_ip < 20 || header->caplen < (bpf_u_int32)(SIZE_ETHERNET + size_ip))
    {
        return 0;
    }

    if (ip->ip_p != IPPROTO_TCP)
    {
        return 0;
    }

    transport_offset = SIZE_ETHERNET + (size_t)size_ip;
    if (header->caplen < (bpf_u_int32)(transport_offset + sizeof(struct sniff_tcp)))
    {
        return 0;
    }

    tcp = (const struct sniff_tcp *)(packet + transport_offset);
    size_tcp = TH_OFF(tcp) * 4;
    if (size_tcp < 20 || header->caplen < (bpf_u_int32)(transport_offset + (size_t)size_tcp))
    {
        return 0;
    }

    size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
    if (size_payload <= 0)
    {
        return 0;
    }

    payload_offset = transport_offset + (size_t)size_tcp;
    if (header->caplen < (bpf_u_int32)payload_offset)
    {
        return 0;
    }

    captured_payload_len = (size_t)(header->caplen - payload_offset);
    if ((size_t)size_payload > captured_payload_len)
    {
        size_payload = (int)captured_payload_len;
    }

    if (size_payload <= 0)
    {
        return 0;
    }

    *payload_ptr = packet + payload_offset;

    inet_ntop(AF_INET, &(ip->ip_src), record->src_ip, sizeof(record->src_ip));
    inet_ntop(AF_INET, &(ip->ip_dst), record->dst_ip, sizeof(record->dst_ip));
    record->src_port = ntohs(tcp->th_sport);
    record->dst_port = ntohs(tcp->th_dport);
    record->payload_size = (unsigned int)size_payload;

    if (!extract_content_type(*payload_ptr, size_payload, record->content_type, sizeof(record->content_type)))
    {
        return 0;
    }

    return is_allowed_content_type(record->content_type);
}

static int append_payload_block(FILE *fp, unsigned int packet_number, unsigned long long feature_id, const struct packet_record *record, const u_char *payload, unsigned long long *file_offset_out)
{
    off_t offset;

    if (fseeko(fp, 0, SEEK_END) != 0)
    {
        return 0;
    }

    offset = ftello(fp);
    if (offset < 0)
    {
        return 0;
    }

    *file_offset_out = (unsigned long long)offset;

    if (fprintf(fp, "=== Packet %u ===\n", packet_number) < 0 ||
        fprintf(fp, "Feature ID: %llu\n", feature_id) < 0 ||
        fprintf(fp, "Source IP: %s\n", record->src_ip) < 0 ||
        fprintf(fp, "Dest IP: %s\n", record->dst_ip) < 0 ||
        fprintf(fp, "Source Port: %u\n", record->src_port) < 0 ||
        fprintf(fp, "Dest Port: %u\n", record->dst_port) < 0 ||
        fprintf(fp, "Content-Type: %s\n", record->content_type) < 0 ||
        fprintf(fp, "Payload Length: %u\n\n", record->payload_size) < 0 ||
        fprintf(fp, "--- RAW DATA ---\n") < 0)
    {
        return 0;
    }

    print_payload(fp, payload, (int)record->payload_size);

    if (fprintf(fp, "\n--- PARSED INFO ---\n") < 0 ||
        fprintf(fp, "feature_id=%llu\n", feature_id) < 0 ||
        fprintf(fp, "content_type=%s\n", record->content_type) < 0 ||
        fprintf(fp, "payload_size=%u\n", record->payload_size) < 0 ||
        fprintf(fp, "=== End Packet %u ===\n\n", packet_number) < 0)
    {
        return 0;
    }

    if (fflush(fp) != 0 || ferror(fp))
    {
        return 0;
    }

    return 1;
}

static int rewind_payload_log(FILE *fp, unsigned long long file_offset)
{
    if (fflush(fp) != 0)
    {
        return 0;
    }

    if (ftruncate(fileno(fp), (off_t)file_offset) != 0)
    {
        return 0;
    }

    if (fseeko(fp, 0, SEEK_END) != 0)
    {
        return 0;
    }

    clearerr(fp);
    return 1;
}

static unsigned long long insert_feature(MYSQL *db, const struct packet_record *record)
{
    char src_ip_escaped[2 * sizeof(record->src_ip) + 1];
    char dst_ip_escaped[2 * sizeof(record->dst_ip) + 1];
    char content_type_escaped[2 * sizeof(record->content_type) + 1];
    char query[1024];

    mysql_real_escape_string(db, src_ip_escaped, record->src_ip, (unsigned long)strlen(record->src_ip));
    mysql_real_escape_string(db, dst_ip_escaped, record->dst_ip, (unsigned long)strlen(record->dst_ip));
    mysql_real_escape_string(db, content_type_escaped, record->content_type, (unsigned long)strlen(record->content_type));

    snprintf(query, sizeof(query),
             "INSERT INTO feature (src_ip, dst_ip, src_port, dst_port, content_type, payload_size) "
             "VALUES ('%s', '%s', %u, %u, '%s', %u)",
             src_ip_escaped,
             dst_ip_escaped,
             record->src_port,
             record->dst_port,
             content_type_escaped,
             record->payload_size);

    if (mysql_query(db, query) != 0)
    {
        fprintf(stderr, "Failed to insert feature: %s\n", mysql_error(db));
        return 0;
    }

    return (unsigned long long)mysql_insert_id(db);
}

static int insert_payload(MYSQL *db, unsigned long long feature_id, const char *file_path, unsigned long long file_offset, const char *data_type)
{
    char file_path_escaped[2049];
    char data_type_escaped[257];
    char query[4096];

    mysql_real_escape_string(db, file_path_escaped, file_path, (unsigned long)strlen(file_path));
    mysql_real_escape_string(db, data_type_escaped, data_type, (unsigned long)strlen(data_type));

    snprintf(query, sizeof(query),
             "INSERT INTO payload (file_path, file_offset, data_type, feature_id) "
             "VALUES ('%s', %llu, '%s', %llu)",
             file_path_escaped,
             file_offset,
             data_type_escaped,
             feature_id);

    if (mysql_query(db, query) != 0)
    {
        fprintf(stderr, "Failed to insert payload: %s\n", mysql_error(db));
        return 0;
    }

    return 1;
}

static MYSQL *open_database(void)
{
    const char *host = getenv("DB_HOST");
    const char *user = getenv("DB_USER");
    const char *pass = getenv("DB_PASS");
    const char *db_name = getenv("DB_NAME");
    const char *port_env = getenv("DB_PORT");
    unsigned int port = DEFAULT_DB_PORT;
    MYSQL *db;

    if (host == NULL || *host == '\0')
    {
        host = DEFAULT_DB_HOST;
    }
    if (user == NULL || *user == '\0')
    {
        user = DEFAULT_DB_USER;
    }
    if (pass == NULL)
    {
        pass = DEFAULT_DB_PASS;
    }
    if (db_name == NULL || *db_name == '\0')
    {
        db_name = DEFAULT_DB_NAME;
    }
    if (port_env != NULL && *port_env != '\0')
    {
        port = (unsigned int)strtoul(port_env, NULL, 10);
    }

    db = mysql_init(NULL);
    if (db == NULL)
    {
        return NULL;
    }

    if (mysql_real_connect(db, host, user, pass, db_name, port, NULL, 0) == NULL)
    {
        fprintf(stderr, "Failed to connect to MySQL: %s\n", mysql_error(db));
        mysql_close(db);
        return NULL;
    }

    mysql_set_character_set(db, "utf8mb4");
    return db;
}

static int ensure_data_directory(void)
{
    if (mkdir("data", 0775) == 0)
    {
        return 1;
    }

    if (errno == EEXIST)
    {
        return 1;
    }

    perror("mkdir data");
    return 0;
}

static int build_payload_log_path(char *buffer, size_t buffer_size)
{
    char cwd[PATH_MAX];

    if (getcwd(cwd, sizeof(cwd)) == NULL)
    {
        return 0;
    }

    if (snprintf(buffer, buffer_size, "%s/%s", cwd, PAYLOAD_LOG_RELATIVE_PATH) >= (int)buffer_size)
    {
        return 0;
    }

    return 1;
}

static int lookup_default_device(char *buffer, size_t buffer_size, char *errbuf)
{
    pcap_if_t *devices = NULL;
    pcap_if_t *device;
    const char *selected = NULL;

    if (pcap_findalldevs(&devices, errbuf) == -1)
    {
        return 0;
    }

    for (device = devices; device != NULL; device = device->next)
    {
        if (device->name == NULL)
        {
            continue;
        }

        if ((device->flags & PCAP_IF_LOOPBACK) == 0)
        {
            selected = device->name;
            break;
        }

        if (selected == NULL)
        {
            selected = device->name;
        }
    }

    if (selected == NULL)
    {
        pcap_freealldevs(devices);
        snprintf(errbuf, PCAP_ERRBUF_SIZE, "No capture devices found");
        return 0;
    }

    snprintf(buffer, buffer_size, "%s", selected);
    pcap_freealldevs(devices);
    return 1;
}

static void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    struct app_state *state = (struct app_state *)args;
    struct packet_record record;
    const u_char *payload;
    unsigned long long feature_id = 0;
    unsigned long long file_offset = 0;
    int payload_written = 0;

    if (!parse_packet_record(header, packet, &record, &payload))
    {
        return;
    }

    if (mysql_query(state->db, "START TRANSACTION") != 0)
    {
        fprintf(stderr, "Failed to start transaction: %s\n", mysql_error(state->db));
        return;
    }

    feature_id = insert_feature(state->db, &record);
    if (feature_id == 0)
    {
        mysql_query(state->db, "ROLLBACK");
        return;
    }

    if (!append_payload_block(state->payload_fp, state->qualified_count + 1, feature_id, &record, payload, &file_offset))
    {
        mysql_query(state->db, "ROLLBACK");
        return;
    }
    payload_written = 1;

    if (!insert_payload(state->db, feature_id, state->payload_file_path, file_offset, record.content_type))
    {
        rewind_payload_log(state->payload_fp, file_offset);
        mysql_query(state->db, "ROLLBACK");
        return;
    }

    if (mysql_query(state->db, "COMMIT") != 0)
    {
        if (payload_written)
        {
            rewind_payload_log(state->payload_fp, file_offset);
        }
        mysql_query(state->db, "ROLLBACK");
        fprintf(stderr, "Failed to commit transaction: %s\n", mysql_error(state->db));
        return;
    }

    state->qualified_count++;

    printf("Accepted packet %u\n", state->qualified_count);
    printf("  Source IP: %s\n", record.src_ip);
    printf("  Dest IP: %s\n", record.dst_ip);
    printf("  Source Port: %u\n", record.src_port);
    printf("  Dest Port: %u\n", record.dst_port);
    printf("  Content-Type: %s\n", record.content_type);
    printf("  Payload Length: %u\n", record.payload_size);
    printf("  Payload Offset: %llu\n\n", file_offset);

    if (state->qualified_count >= TARGET_PACKET_COUNT)
    {
        pcap_breakloop(state->handle);
    }
}

int main(int argc, char **argv)
{
    char dev_buffer[128];
    char *dev = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct bpf_program fp;
    bpf_u_int32 mask;
    bpf_u_int32 net;
    struct app_state state;
    int loop_result;

    memset(&state, 0, sizeof(state));
    memset(dev_buffer, 0, sizeof(dev_buffer));
    memset(errbuf, 0, sizeof(errbuf));

    if (argc == 2)
    {
        dev = argv[1];
    }
    else if (argc > 2)
    {
        fprintf(stderr, "error: unrecognized command-line options\n\n");
        print_app_usage();
        exit(EXIT_FAILURE);
    }
    else
    {
        if (!lookup_default_device(dev_buffer, sizeof(dev_buffer), errbuf))
        {
            fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
            exit(EXIT_FAILURE);
        }
        dev = dev_buffer;
    }

    if (!ensure_data_directory())
    {
        exit(EXIT_FAILURE);
    }

    if (!build_payload_log_path(state.payload_file_path, sizeof(state.payload_file_path)))
    {
        fprintf(stderr, "Failed to build payload log path\n");
        exit(EXIT_FAILURE);
    }

    state.payload_fp = fopen(PAYLOAD_LOG_RELATIVE_PATH, "ab+");
    if (state.payload_fp == NULL)
    {
        perror("fopen payload log");
        exit(EXIT_FAILURE);
    }

    state.db = open_database();
    if (state.db == NULL)
    {
        fclose(state.payload_fp);
        exit(EXIT_FAILURE);
    }

    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1)
    {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
        net = 0;
        mask = 0;
    }

    printf("Device: %s\n", dev);
    printf("Target packets: %d\n", TARGET_PACKET_COUNT);
    printf("Filter expression: %s\n", FILTER_EXP);
    printf("Payload log: %s\n", state.payload_file_path);

    handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
    if (handle == NULL)
    {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        mysql_close(state.db);
        fclose(state.payload_fp);
        exit(EXIT_FAILURE);
    }

    if (pcap_datalink(handle) != DLT_EN10MB)
    {
        fprintf(stderr, "%s is not an Ethernet\n", dev);
        pcap_close(handle);
        mysql_close(state.db);
        fclose(state.payload_fp);
        exit(EXIT_FAILURE);
    }

    if (pcap_compile(handle, &fp, FILTER_EXP, 0, net) == -1)
    {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", FILTER_EXP, pcap_geterr(handle));
        pcap_close(handle);
        mysql_close(state.db);
        fclose(state.payload_fp);
        exit(EXIT_FAILURE);
    }

    if (pcap_setfilter(handle, &fp) == -1)
    {
        fprintf(stderr, "Couldn't install filter %s: %s\n", FILTER_EXP, pcap_geterr(handle));
        pcap_freecode(&fp);
        pcap_close(handle);
        mysql_close(state.db);
        fclose(state.payload_fp);
        exit(EXIT_FAILURE);
    }

    state.handle = handle;
    loop_result = pcap_loop(handle, -1, got_packet, (u_char *)&state);

    if (loop_result == -1)
    {
        fprintf(stderr, "pcap_loop failed: %s\n", pcap_geterr(handle));
    }

    pcap_freecode(&fp);
    pcap_close(handle);
    mysql_close(state.db);
    fclose(state.payload_fp);

    printf("Capture complete. Accepted %u packets.\n", state.qualified_count);

    return loop_result == -1 ? EXIT_FAILURE : EXIT_SUCCESS;
}
