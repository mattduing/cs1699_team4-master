// You will build this in project part B - this is merely a
// stub that does nothing but integrate into the stack

// For project parts A and B, an appropriate binary will be
// copied over as part of the build process



#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>


#include <iostream>

#include "Minet.h"
#include "buffer.h"
#include "ip.h"
#include "tcp.h"
#include "packet.h"
#include "tcpstate.h"
using namespace std;
/*
struct TCPState {
    // need to write this
    std::ostream & Print(std::ostream &os) const {
	os << "TCPState()" ;
	return os;
    }
};*/


void create_send_packet(Packet &send_packet,Connection conn, unsigned char flags, int sz,const unsigned int &seq_num, const unsigned int &ack_num);




int main(int argc, char * argv[]) {
    MinetHandle mux;
    MinetHandle sock;
    ConnectionList<TCPState> clist;

    MinetInit(MINET_TCP_MODULE);

    mux = MinetIsModuleInConfig(MINET_IP_MUX) ?
	MinetConnect(MINET_IP_MUX) :
	MINET_NOHANDLE;

    sock = MinetIsModuleInConfig(MINET_SOCK_MODULE) ?
	MinetAccept(MINET_SOCK_MODULE) :
	MINET_NOHANDLE;

    if ( (mux == MINET_NOHANDLE) &&
	 (MinetIsModuleInConfig(MINET_IP_MUX)) ) {

	MinetSendToMonitor(MinetMonitoringEvent("Can't connect to ip_mux"));

	return -1;
    }

    if ( (sock == MINET_NOHANDLE) &&
	 (MinetIsModuleInConfig(MINET_SOCK_MODULE)) ) {

	MinetSendToMonitor(MinetMonitoringEvent("Can't accept from sock_module"));

	return -1;
    }

    cerr << "tcp_module STUB VERSION handling tcp traffic.......\n";

    MinetSendToMonitor(MinetMonitoringEvent("tcp_module STUB VERSION handling tcp traffic........"));

    MinetEvent event;
    double timeout = 1;

    while (MinetGetNextEvent(event, timeout) == 0) {

	if ((event.eventtype == MinetEvent::Dataflow) &&
	    (event.direction == MinetEvent::IN)) {

	    if (event.handle == mux) {
		// ip packet has arrived!
	    	Packet p;
		unsigned short len;
		bool checksumok;
		MinetReceive(mux, p);
		Buffer data;

		len = TCPHeader::EstimateTCPHeaderLength(p);
		p.ExtractHeaderFromPayload<TCPHeader>(len);
		TCPHeader tcp_head = p.FindHeader(Headers::TCPHeader);
		IPHeader ip_head = p.FindHeader(Headers::IPHeader);
		//print header info
		cerr << "\n\nHeader: " << tcp_head << endl;


		//checksum check
		checksumok = tcp_head.IsCorrectChecksum(p);
		cerr << "\nChecksum Ok? " << checksumok << endl;
		if(!checksumok){
		printf("CHECKSUM ERROR!!\n");
		}

		unsigned char f;
		tcp_head.GetFlags(f);

		//create connection
		Connection c;
		ip_head.GetDestIP(c.src);
		ip_head.GetSourceIP(c.dest);
		ip_head.GetProtocol(c.protocol);
		tcp_head.GetDestPort(c.srcport);
		tcp_head.GetSourcePort(c.destport);
		cerr << "Connection: " << c << "\n" << endl;


		unsigned short total_len;
		ip_head.GetTotalLength(total_len);
		unsigned char ip_len;
		ip_head.GetHeaderLength(ip_len);
		unsigned char tcp_len;
		tcp_head.GetHeaderLen(tcp_len);
		unsigned int sequence_num;
		tcp_head.GetSeqNum(sequence_num);
		unsigned int ack_num;
		tcp_head.GetAckNum(ack_num);
    unsigned short window_size;
    tcp_head.GetWinSize(window_size);

		data = p.GetPayload().ExtractFront(total_len - ((tcp_len + ip_len)*4));
		cerr << "DATA: " << data << endl;
		//data.GetData(data_char, sizeof(data), 0);




		//search the connection list to see if it exists
		ConnectionList<TCPState>::iterator mapping = clist.FindMatching(c);
		//if the connection is found in the list somewhere (not the end)
		if(mapping==clist.end()){
		cerr << "Connection not found in the list" << endl;
		//	unsigned short temp_state = mapping.state.GetState();

		}else{
			cerr << "FOUND!!!!!!!!!!\n\n\n\n" << endl;
		}

		unsigned short tcp_state = mapping->state.GetState();
		cerr << "STATE: " << tcp_state << endl;


		Packet send_packet;


		switch(tcp_state){

			case CLOSED:{
				break;//should not be hit
			}
			case LISTEN:{

				//if there has been a SYN received we need to send back the SYN_ACK
				if(IS_SYN(f)){
					cerr<< "IS SYN!!!!!!" << endl;


				        if (mapping->state.GetState() == SYN_RCVD){
						cerr<< "MAPPING SET CORRECTLY\n\n" << endl;
					}
					mapping->state.SetLastRecvd(sequence_num);
					mapping->bTmrActive = true;
                    mapping->timeout=Time() + 10;

					SET_ACK(f);
					SET_SYN(f);

					create_send_packet(send_packet, c, f, 0, ack_num, sequence_num + 1);
					TCPHeader tcp_head = send_packet.FindHeader(Headers::TCPHeader);
					cerr << "PACKET HEAD!!: send_packet--> " << tcp_head << endl;

					int send = MinetSend(mux, send_packet);
					MinetSend(mux,send_packet);
					cerr << "SEND STATUS : " << send << endl;

					mapping->state.SetState(SYN_RCVD);
					mapping->state.SetLastSent(mapping->state.GetLastSent()+1);
				}
				break;
			}
			case SYN_RCVD:{
				cerr << "\n\n\n\nSYN_RCVD\n\n\n\n\n\n" << endl;

				if(IS_ACK(f)){

				//need to send an ACK and  set state to ESTABLISHED
				mapping->state.SetState(ESTABLISHED);
        mapping->state.SetLastAcked(ack_num);
        mapping->state.SetSendRwnd(window_size);
        mapping->state.last_sent = mapping->state.last_sent + 1;
        mapping->bTmrActive = false;
				cerr << "SYN_RCVD !!!!!!!! "<< endl;

				static SockRequestResponse * write = NULL;
				//cerr << "CONN: " << mapping->connection << endl;
				write = new SockRequestResponse(WRITE, mapping->connection,data,0,EOK);
				MinetSend(sock, *write);
        delete write;
				break;
				}
			}
			case SYN_SENT:{
				//represents waiting for a matching connection request after having sent a connectioni
				if(IS_SYN(f) && IS_ACK(f)){
					cerr << "SYN_SENT!!@@@!@!@!@!@ IS SYN" << endl;
          mapping->state.SetSendRwnd(window_size);
          mapping->state.SetLastRecvd(sequence_num + 1);
          mapping->state.last_acked = ack_num;
          //make ack packet
          mapping->state.last_sent = mapping->state.last_sent + 1;
          SET_ACK(f);
          create_send_packet(send_packet, c, f, 0, 0, 0);
          MinetSend(mux, send_packet);
          mapping->state.SetState(ESTABLISHED);
          mapping->bTmrActive = false;
				}
				break;
			}
			case SYN_SENT1:{
				break;
			}
			case ESTABLISHED:{
				//represents an open connection for a confiming connection request acknowledgment after having received and sent a connection request
				cerr << "ESTABLISHED " << endl;
        if(IS_PSH(f) && IS_ACK(f)) {
  					cerr << "IS_PSH + IS_ACK" << endl;
  					cerr << "Received \"" << data << "\", buffer size: " << data.GetSize() << "." << endl;
  					mapping->state.SetSendRwnd(window_size);

  					mapping->state.last_recvd = sequence_num + data.GetSize();
  					mapping->state.last_acked = ack_num;

  					// Write to socket
  					mapping->state.RecvBuffer.AddBack(data);
  					SockRequestResponse write (WRITE, mapping->connection, mapping->state.RecvBuffer, mapping->state.RecvBuffer.GetSize(), EOK);
  					MinetSend(sock,write);

  					// make ACK packeet
            SET_ACK(f);
  					create_send_packet(send_packet, c, f, 0, 0, 0);
  					MinetSend(mux, send_packet);
  			}
  			// client closes connection
  			else if(IS_FIN(f) && IS_ACK(f)) {
  					cerr << "IS_FIN + IS_ACK" << endl;
  					mapping->state.SetState(CLOSE_WAIT);
  					mapping->state.SetSendRwnd(window_size);
  					mapping->bTmrActive = true;
                    mapping->timeout=Time() + 8;   

  					mapping->state.last_recvd = sequence_num + 1;
  					mapping->state.last_acked = ack_num;

  					//make ACK packet
            SET_ACK(f);
  					create_send_packet(send_packet, c, f, 0, 0, 0);
  					MinetSend(mux, send_packet);
  			}
  			// we are the client, the server is ACK'ing our packet
  			else if(IS_ACK(f)) {
  					cerr << "ACK received" << endl;
  					mapping->state.SetLastRecvd((unsigned int)sequence_num);
  					mapping->state.last_acked = ack_num;
  					mapping->bTmrActive = false;
  			}
  			else {
  					cerr << "Unknown packet: " << endl;
  			}

  			break;
  		// waiting for FIN/ACK in response to our FIN/ACK
  		case FIN_WAIT1:
  			// got FIN/ACK from server
  			if(IS_FIN(f) && IS_ACK(f)) {
  					cerr << "===============START CASE FIN_WAIT1 + IS_FIN + IS_ACK===============\n" << endl;
  					mapping->state.SetState(FIN_WAIT2);
  					mapping->state.SetSendRwnd(window_size);

  					mapping->state.last_recvd = sequence_num + 1;
  					mapping->state.last_acked = ack_num;


  					// make ACK packet
                    SET_ACK(f);
                    mapping->bTmrActive = true;
                    mapping->timeout=Time() + (2*MSL_TIME_SECS);
  					create_send_packet(send_packet, c, f, 0, 0, 0);
  					MinetSend(mux, send_packet);
  			}


				break;
			}
			case SEND_DATA:{
				break;
			}
			case CLOSE_WAIT:{
				if(IS_ACK(f)) {
					cerr << "CLOSE_WAIT - IS_ACK" << endl;
					SockRequestResponse close;
					close.type = CLOSE;
					close.connection = mapping->connection;
					close.bytes = 0;
					close.error = EOK;
					MinetSend(sock, close);
					clist.erase(mapping);
				break;
			}

			case CLOSING:{
				break;
			}
			case LAST_ACK:{
        if (IS_ACK(f)) {

          cerr << "LAST_ACK" << endl;
          mapping->state.SetState(CLOSED);
          clist.erase(mapping);
				break;
			}
			case FIN_WAIT2:{
				    //mapping->state.SetSendRwnd(window_size);
					mapping->state.last_recvd = sequence_num + 1;
					mapping->state.last_acked = ack_num;

					//make ACK packet
          SET_ACK(f);
					create_send_packet(send_packet, c, f, 0, 0, 0);
					mapping->bTmrActive = true;
                    mapping->timeout=Time() + (2*MSL_TIME_SECS);
					MinetSend(mux, send_packet);


					SockRequestResponse close;
					close.type = CLOSE;
					close.connection = mapping->connection;
					close.bytes = 0;
					close.error = EOK;
					MinetSend(sock, close);

					clist.erase(mapping);
				break;
			}
			case TIME_WAIT:{
				break;
			}








		}







		}

	   if (event.handle == sock) {
		// socket request or response has arrived
		SockRequestResponse request;
		int sequence_num = rand()%4294967295;

		MinetReceive(sock, request);

		ConnectionList<TCPState>::iterator cs = clist.FindMatching(request.connection);

		if(cs == clist.end()){
		//no connection --> create one
			switch(request.type){

			//Connect = 0
			//Accept = 1
			//Write = 2
			//Close = 4

			case CONNECT:{

				//active open
				cerr << "CONNECT\n\n\n\n" << endl;
				TCPState tcp_state(sequence_num, SYN_SENT, 1);






				//create connection
				Connection c;
				c=request.connection;


				ConnectionToStateMapping<TCPState> mapping (request.connection, Time(), tcp_state, false);
				mapping.connection = c;
				mapping.state = tcp_state;
				clist.push_front(mapping);


				unsigned char flags = 0;
				SET_SYN(flags);
				Packet send_packet;

				create_send_packet(send_packet, c, flags, 0, 0, 0 );
				MinetSend(sock, send_packet);

				//setup the response
				SockRequestResponse response;
				response.bytes = 0;
				response.type = STATUS;
				response.connection = request.connection;
				MinetSend(sock, response);




				break;
			}case ACCEPT:{
				printf("ACCEPT\n\n");
				TCPState tcp_state(sequence_num, LISTEN, 1);

				Connection c;
				c = request.connection;


				ConnectionToStateMapping<TCPState> mapping(request.connection, Time(), tcp_state, false);
				mapping.connection  = c;
				mapping.state = tcp_state;
				clist.push_front(mapping);
				cerr << "Mapping " << mapping.connection << " with State: " << mapping.state.GetState() <<  endl;


				//setup the response
				SockRequestResponse response;
				response.bytes = 0;
				response.type = STATUS;
				response.connection = request.connection;
				MinetSend(sock, response);
				break;
			}case WRITE:{
				printf("\n\nWRITE\n\n");
				SockRequestResponse response;
				response.connection = request.connection;
				response.bytes = 0;
				response.error = ENOMATCH;
				response.type = STATUS;

				break;
			}case CLOSE:{
				printf("CLOSE\n\n");
				//send fin and close connection
				//create connection
				Connection c;
				c=request.connection;


				SockRequestResponse response;
				response.connection = request.connection;
				response.type = STATUS;
				response.error = EOK;

				cs->state.SetState(FIN_WAIT1);
				Packet p;

				unsigned char f;
				SET_FIN(f);
				SET_ACK(f);
				create_send_packet(p, c, f, 0,0,0 );

				MinetSend(mux, p);
				MinetSend(sock, response);
				break;


			}case STATUS:{
				//kill the connection
				break;
				}
			case FORWARD:{
				break;
			}

			}

		}else{
		//connection exists --> take action

		}

	 }
	}

	if (event.eventtype == MinetEvent::Timeout) {
	    // timeout ! probably need to resend some packets
	}


   }

    MinetDeinit();

    return 0;
}
}
}





//create a packet before sending it in minet
void create_send_packet(Packet &send_packet,Connection conn, unsigned char flags, int sz, const unsigned int &seq_num, const unsigned int &ack_num){

TCPHeader tcp_head;
IPHeader ip_head;
cerr << "GOING THROUGH 1 srcport" << conn.srcport << " dest port  " << conn.destport << endl;



ip_head.SetDestIP(conn.dest);
ip_head.SetSourceIP(conn.src);
ip_head.SetTotalLength(IP_HEADER_BASE_LENGTH+ TCP_HEADER_BASE_LENGTH + sz);
ip_head.SetProtocol(IP_PROTO_TCP);
send_packet.PushFrontHeader(ip_head);




tcp_head.SetDestPort(conn.destport, send_packet);
tcp_head.SetSourcePort(conn.srcport, send_packet);
tcp_head.SetFlags(flags, send_packet);
tcp_head.SetHeaderLen(5,send_packet);
tcp_head.SetAckNum(ack_num, send_packet);
tcp_head.SetUrgentPtr(0,send_packet);
tcp_head.SetSeqNum(seq_num, send_packet);
//cerr << "THROUGH TCPHEAD!!" << endl;
send_packet.PushBackHeader(tcp_head);
cerr << "Create Send Packet Packet TCP Head " << tcp_head << " \n\nPACKET?? " << send_packet << endl;
}

/*
int SendData(MinetHandle &mux, MinetHandle &sock, ConnectionToStateMapping<TCPState> &CTSM, Buffer data) {
                                       
        cerr << "Sending data" << endl;
		Packet p;
        CTSM.state.SendBuffer.AddBack(data);
        unsigned int data_remaining = data.GetSize();
        
        while( data_remaining!= 0) {
                unsigned int data_to_send = min(data_remaining, TCP_MAXIMUM_SEGMENT_SIZE);
                p = CTSM.state.SendBuffer.Extract(0, data_to_send);
                create_send_packet(p, c, flags, 0, 0, 0 );
                MinetSend(mux, p);
                
                //theCTSM.state.SetLastSent(theCTSM.state.GetLastSent()+bytesToSend);
                CTSM.state.last_sent = CTSM.state.last_sent + data_to_send;
				
                data_remaining -= data_to_send;
        }
	return data_remaining;
}
*/

