#include <cstdio>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>
#include <iostream>

#include <libnetfilter_queue/libnetfilter_queue.h>

#include <string>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <fstream>

//sudo apt-get install sqlite3 libsqlite3-dev
#include <sqlite3.h>

#define DB_FILE "test.db"

using std::cout;
using std::cin;
using std::endl;
using std::string;

int state;

void useage(){
	printf("syntax : 1m-block <site list file>\n");
	printf("sample : 1m-block top-1m.txt\n");
}

void make_db(char* argv, sqlite3* db, int rc, char* err_msg){
	std::fstream fs;
	string str_buf;
	size_t cur;
	fs.open(argv, std::ios::in);

	rc = sqlite3_open(DB_FILE, &db);

	if(rc != SQLITE_OK)
	{
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        
        exit(-1);
    }

	string sql = "Drop TABLE IF EXISTS Site;"
				 "CREATE TABLE Site(Id INT, URL TEXT);";
	
	rc = sqlite3_exec(db, sql.c_str(), 0, 0, &err_msg);
	if (rc != SQLITE_OK )
    {
        fprintf(stderr, "SQL error: %s\n", err_msg);
        
        sqlite3_free(err_msg);        
        sqlite3_close(db);
        
        exit(-1);
    }

	cout << "making DB table!" << endl;
	while(!fs.eof())
	{
		getline(fs, str_buf);
		cur = str_buf.find(',');
		if(cur != string::npos) 
		{
			//cout << str_buf.substr(0, cur) << " " << str_buf.substr(cur+1, str_buf.length()-1) << endl; 
			sql.clear();
			sql = "INSERT INTO Site VALUES(";
			sql.append(str_buf.substr(0, cur));
			sql.append(", '");
			sql.append(str_buf.substr(cur+1, str_buf.length()-1));
			sql.append("');");

			// cout << sql << endl;

			rc = sqlite3_exec(db, sql.c_str(), 0, 0, &err_msg);
			if (rc != SQLITE_OK )
			{
				fprintf(stderr, "SQL error: %s\n", err_msg);
				
				sqlite3_free(err_msg);        
				sqlite3_close(db);
				
				exit(-1);
			}
    	}
	}
	fs.close();
}

bool check_http(string payload)
{
	const char* methods[] = {"GET","POST", "HEAD","PUT","DELETE","CONNECT","OPTIONS","TRACE","PATCH"};
	bool res = false;
	for(int i = 0 ; i < sizeof(methods)/sizeof(char *); i++)
	{
		if (payload.find(methods[i]) != string::npos) {
			res = true;
			break;
		}
	}
	return res;
}

bool search(string _host)
{
	sqlite3 *db;
	char *err_msg = 0;
	sqlite3_stmt *res;

	int rc = sqlite3_open(DB_FILE, &db);
	
	if (rc != SQLITE_OK)
    {
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        
        exit(-1);
    }

	string sql = "SELECT * FROM Site WHERE URL = \"";
	sql.append(_host);
	sql.append("\"");

	cout << sql << endl;

	rc = sqlite3_prepare_v2(db, sql.c_str(), -1, &res, 0);
	if (rc != SQLITE_OK)
    {
        fprintf(stderr, "Failed to execute statement: %s\n", sqlite3_errmsg(db));
    }

	int step = sqlite3_step(res);

	if (step == SQLITE_ROW)
    {
        printf("%s: ", sqlite3_column_text(res, 0));
        printf("%s\n", sqlite3_column_text(res, 1));
		return true;
    } 

	sqlite3_finalize(res);
    sqlite3_close(db);
	return false;
}

/* returns packet id */
static u_int32_t print_pkt (struct nfq_data *tb)
{
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	u_int32_t mark,ifi;
	int ret;
	unsigned char *data;

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) {
		id = ntohl(ph->packet_id);
		// printf("hw_protocol=0x%04x hook=%u id=%u ",
		// 	ntohs(ph->hw_protocol), ph->hook, id);
	}

	hwph = nfq_get_packet_hw(tb);
	if (hwph) {
		int i, hlen = ntohs(hwph->hw_addrlen);

		// printf("hw_src_addr=");
		// for (i = 0; i < hlen-1; i++)
		// 	printf("%02x:", hwph->hw_addr[i]);
		// printf("%02x ", hwph->hw_addr[hlen-1]);
	}


	ret = nfq_get_payload(tb, &data);
	if (ret >= 0){
		ip* _ip = (ip*)(data);

		if(_ip->ip_p == IPPROTO_TCP){
			tcphdr* _tcp = (tcphdr*)(data + 4*(_ip->ip_hl));
			
			string _http = string( (char*)(data + 4*(_ip->ip_hl) + 4*(_tcp->th_off)) );
			string get_host;

			string chk_http = _http.substr(0,10);
			if(check_http(chk_http)){
				if (_http.find("Host: ") != string::npos) {
					int Fpos = _http.find("Host: ");
				
					get_host = _http.substr(Fpos+6);
					if(get_host.find(0x0D) != string::npos) {
						int Lpos = get_host.find(0x0D);
						get_host = get_host.substr(0,Lpos);

						cout << "http's host is " << get_host << endl;
						if(search(get_host)){
							state = NF_DROP;
							cout << "drop!" << endl;
						}
					}
				}
			}
			
		}
	}

	// fputc('\n', stdout);

	return id;
}


static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{
	state = NF_ACCEPT;
	u_int32_t id = print_pkt(nfa);
	// printf("entering callback\n");
	return nfq_set_verdict(qh, id, state, 0, NULL);
}

int main(int argc, char **argv)
{
	sqlite3* db;
	sqlite3_stmt* res;
	char *err_msg = 0;

	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));

	if(argc != 2){
		useage();
		exit(-1);
	}

	//sql test
	int rc = sqlite3_open(":memory:", &db);
    
    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        
        return 1;
    }

	rc = sqlite3_prepare_v2(db, "SELECT SQLITE_VERSION()", -1, &res, 0);
	if (rc != SQLITE_OK)
	{
		fprintf(stderr, "Failed to fetch data: %s\n", sqlite3_errmsg(db));
		sqlite3_close(db);
		
		return 1;
	}
	
	rc = sqlite3_step(res);
    if (rc == SQLITE_ROW)
    {
        printf("sqlite3 version : %s\n", sqlite3_column_text(res, 0));
    }

	// read csv and insert to db
	char input;
	while(true){
		cout << "Do you want to make new DB table? [Y/N] : ";
		input = getchar();
		while (getchar() != '\n');
		if(input == 'Y' || input == 'y' || input == 13){
			make_db(argv[1], db, rc, err_msg);
			break;
		}
		else if(input == 'N' || input == 'n'){
			break;
		}
		else
		{
			continue;
		}
		
		
	}

	
	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h,  0, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(h);

	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			// printf("pkt received\n");
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		/* if your application is too slow to digest the packets that
		 * are sent from kernel-space, the socket buffer that we use
		 * to enqueue packets may fill up returning ENOBUFS. Depending
		 * on your application, this error may be ignored. nfq_nlmsg_verdict_putPlease, see
		 * the doxygen documentation of this library on how to improve
		 * this situation.
		 */
		if (rv < 0 && errno == ENOBUFS) {
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);


	sqlite3_finalize(res);
    sqlite3_close(db);

	exit(0);
}
