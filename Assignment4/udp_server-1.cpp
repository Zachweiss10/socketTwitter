#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctime>
#include <random>
#include <map>
#include <time.h>
#include <string>
#include <fstream>
#include <iostream>
#include <algorithm>
using namespace std;

struct header {

    char magic1;
    char magic2;
    char opcode;
    char payload_len;

    uint32_t token;
    uint32_t msg_id;
};
char tag[] = "<>";

const int h_size = sizeof(struct header);

// These are the constants indicating the states.
// CAUTION: These states have nothing to do with the states on the client.
#define STATE_OFFLINE          0
#define STATE_ONLINE           1
#define STATE_MSG_FORWARD      2
// Now you can define other states in a similar fashion.

// These are the events
// CAUTION: These events have nothing to do with the states on the client.
#define EVENT_NET_LOGIN                 80
#define EVENT_NET_POST                  81
// Now you can define other events from the network.
#define EVENT_NET_INVALID               255

#define EVENT_LOGIN                     254
#define EVENT_SUBSCRIBE                 253
#define EVENT_UNSUBSCRIBE               252
#define EVENT_POST                      251
#define EVENT_FORWARD_ACK               249
#define EVENT_RETRIEVE                  248
#define EVENT_LOGOUT                    247
#define EVENT_INVALID                   246
#define EVENT_SESSION_RESET             245
#define EVENT_SERVER_RESET              244

// These are the constants indicating the opcodes.
// CAUTION: These opcodes must agree on both sides.
#define OPCODE_RESET                    0x00
#define OPCODE_RESET2                   0x01
#define OPCODE_MUST_LOGIN_FIRST_ERROR   0xF0
#define OPCODE_LOGIN                    0x10
// Now you can define other opcodes in a similar fashion.
/*New OPCODES*/
#define MAGIC_1 0x5A
#define MAGIC_2 0x57
#define session_reset 0x00
#define must_login_first_error 0xF0
#define login 0x10
#define successful_login_ack 0x80
#define failed_login_ack 0x11
#define subscribe 0x20
#define successful_subscribe_ack 0x90
#define failed_subscribe_ack 0x91
#define unsubscribe 0x21
#define successful_unsubscribe_ack 0xA0
#define failed_unsubscribe_ack 0xA1
#define post 0x30
#define post_ack 0xB0
#define forward 0xB1
#define forward_ack 0x31
#define retrieve 0x40
#define retrieve_ack 0xC0
#define end_of_retrieve_ack 0xC1
#define logout 0x1F
#define logout_ack 0x8F
#define push_ack 0xb2

union N{
    char byte[1];
    int integer;
};
// This is a data structure that holds important information on a session.
struct session {

    char client_id[32]; // Assume the client ID is less than 32 characters.
    struct sockaddr_in client_addr; // IP address and port of the client
                                    // for receiving messages from the 
                                    // server.
    time_t last_time; // The last time when the server receives a message
                      // from this client.
    uint32_t token;        // The token of this session.
    int state;        // The state of this session, 0 is "OFFLINE", etc.

    // TODO: You may need to add more information such as the subscription
    // list, password, etc.
};
map<uint32_t,session *> sessionsMap;

// TODO: You may need to add more structures to hold global information
// such as all registered clients, the list of all posted messages, etc.
// Initially all sessions are in the OFFLINE state.
struct Client{
    const char * clientID;
    const char * password;
    char subscriber[32];
    session sess;
};
Client clients[3];
Client client_a;
Client client_b;
Client client_c;

int parse_the_event_from_the_datagram(char code){
    //printf("parse_the_event_from_the_datagram()\n");
    int event = code;
    if(code == login)
        event = EVENT_LOGIN;
    else if(code == subscribe)
        event = EVENT_SUBSCRIBE;
    else if(code == unsubscribe)
        event = EVENT_UNSUBSCRIBE;
    else if(code == post)
        event = EVENT_POST;
    else if(code == forward)
        event = EVENT_NET_POST;
    else if(code == forward_ack)
        event = EVENT_FORWARD_ACK;
    else if(code == retrieve)
        event = EVENT_RETRIEVE;
    else if (code == logout)
        event = EVENT_LOGOUT;
    else if (code == OPCODE_RESET)
        event = EVENT_SESSION_RESET;
    else if (code == OPCODE_RESET2)
        event = EVENT_SERVER_RESET;
    else
        event = EVENT_INVALID;
    //printf("parse_the_event_from_the_datagram()ends\n");
    return event;
}

session * find_the_session_by_token(uint32_t token){
    //printf("find_the_session_by_token()\n");
    session *s;
    map<uint32_t,session *>::iterator it;
    it = sessionsMap.find(token);
    if(it != sessionsMap.end())
        return sessionsMap.find(token)->second;

    //printf("find_the_session_by_token()END\n");
    return s;
}

int check_id_password(char * user_id,char * password, session * sess){
   // printf("check_id_password()\n");
    for(int i = 0; i<3; i++)
    {
        //printf("client[%d].clientID = %s\n",i ,clients[i].clientID );
        //printf("user_id: %s, passord: %s\n",user_id,password );
        if(!strcmp(clients[i].clientID,user_id) && !strcmp(clients[i].password,password)){
            clients[i].sess = *sess;
            return 1;
        }
    }
    //printf("check_id_password()END\n");
    return 0;
}
uint32_t generate_a_random_token(){
    srand(time(NULL));
    uint32_t num = rand() % 4294967295;
    return num;
}
session * add_to_session_map(uint32_t token, char * str){
    //printf("find_this_client_in_the_session_array()\n");
    session * s=(session *)malloc(sizeof(session));
    sessionsMap.insert(pair<uint32_t, session*>(token, s));
    //printf("add_to_session_map()END\n");
    return s;
}
using namespace std;

bool reverse_file(const char* input, const char* output)
{
    streamsize count=0;
    streamoff size=0,pos;
    char buff[100];

    ifstream fin(input);
    ofstream fout(output);

    if(fin.fail() || fout.fail()){
        return false;
    }

    fin.seekg(0, ios::end);
    size = fin.tellg();
    fin.seekg(0);
    while(!fin.eof()){  
        fin.read(buff, 100);
        count = fin.gcount();
        reverse(buff,buff+count);
        pos = fin.tellg();
        if(pos<0) {
            pos = size;
        }
        fout.seekp(size - pos);
        fout.write(buff,count);
    }
    return true;
}

bool reverse_file_lines(const char* input, const char* output)
{
    streamsize count=0;

    char buff[100];

    ifstream fin(input);
    ofstream fout(output);

    if(fin.fail() || fout.fail()){
        return false;
    }

    while(!fin.eof()){  
        fin.getline(buff, 100);
    /*if BUFFSIZE is smallest then line size gcount will return 0, 
        but I didn't handle it...*/
        count = fin.gcount();
        if(buff[count-1]==0)count--;
        reverse(buff,buff+count);
        fout.write(buff,count);
        if(!fin.eof()){
            fout<<endl;
        }
    }
    return true;
}



void writeFile(session * cs, char * client_id, char * text, int size){
    char clientName[sizeof(client_id)+1];
    strcpy(clientName, client_id);
    char tag[] = "<>";
    char str[36];
    char texts[size];
    strcpy(str,client_id);
    strcat(str,".txt");
    strcpy(texts,text);
    FILE * file = fopen(str, "ab+");
    if(file!=NULL){
    fseek(file, 0 , SEEK_SET);
    fwrite(cs->client_id, sizeof(char), sizeof(clientName)-1, file);
    fwrite(tag, sizeof(char), sizeof(tag)-1, file);
    fwrite(texts, sizeof(char), sizeof(texts), file);
    //fclose(file);
    fclose(file);
    }

    //fstream fin(str, in);
    
}

void add_the_session_to_clientStruct(session *cs){
    for(int i =0; i<3; i++){
        if (!strcmp(clients[i].clientID,cs->client_id)){
            clients[i].sess = *cs;
            return;
        }
    }
    printf("Couldn't add %s to clientStruct\n",cs->client_id );
}




int main() {
/*    client_a.clientID = (char *) malloc(8);
    client_a.password = (char *) malloc(8);
    client_b.clientID = (char *) malloc(8);
    client_b.password = (char *) malloc(8);
    client_c.clientID = (char *) malloc(8);
    client_c.password = (char *) malloc(8);*/
    client_a.clientID= "client_a";
    client_a.password = "password";
    client_b.clientID="client_b";
    client_b.password = "password";
    client_c.clientID="client_c";
    client_c.password = "password";
    clients[0] = client_a;
    clients[1] = client_b;
    clients[2] = client_c;
    int ret;
    int sockfd;
    struct sockaddr_in serv_addr, cli_addr;
    char send_buffer[1024];
    char recv_buffer[1024];
    int recv_len;
    socklen_t len;
    long int lasttime;

    // You may need to use a std::map to hold all the sessions to find a 
    // session given a token. I just use an array just for demonstration.
    // Assume we are dealing with at most 16 clients, and this array of
    // the session structure is essentially our user database

    // Now you need to load all users' information and fill this array.
    // Optionally, you can just hardcode each user.

    // This current_session is a variable temporarily hold the session upon
    // an event.
    struct session *current_session;
    int token;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        printf("socket() error: %s.\n", strerror(errno));
        return -1;
    }

    // The servaddr is the address and port number that the server will 
    // keep receiving from.
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(32000);

    bind(sockfd, 
         (struct sockaddr *) &serv_addr, 
         sizeof(serv_addr));

    // Same as that in the client code.
    struct header *ph_send = (struct header *)send_buffer;
    struct header *ph_recv = (struct header *)recv_buffer;

    while (1) {


        // Note that the program will still block on recvfrom()
        // You may call select() only on this socket file descriptor with
        // a timeout, or set a timeout using the socket options.
        memset(send_buffer,0, sizeof(send_buffer));
        len = sizeof(cli_addr);
        recv_len = recvfrom(sockfd, // socket file descriptor
                 recv_buffer,       // receive buffer
                 sizeof(recv_buffer),  // number of bytes to be received
                 0,
                 (struct sockaddr *) &cli_addr,  // client address
                 &len);             // length of client address structure

        if (recv_len <= 0) {
            printf("recvfrom() error: %s.\n", strerror(errno));
            return -1;
        }

        //printf("server is online\n");

        int event=0;
        // Now we know there is an event from the network
        // TODO: Figure out which event and process it according to the
        // current state of the session referred.
        struct session *cs;
        event = parse_the_event_from_the_datagram(ph_recv->opcode);
        if(!event == EVENT_LOGIN){
        uint32_t token = ph_recv->token;
        cs->last_time = time(NULL);
        }
        // This is the current session we are working with.
        cs = find_the_session_by_token(token);
        
        

        // Record the last time that this session is active.
        
        if (event == EVENT_LOGIN) {
            // For a login message, the current_session should be NULL and
            // the token is 0. For other messages, they should be valid.

            char *id_password = recv_buffer + h_size;

            char *delimiter = strchr(id_password, '&');
            char *password = delimiter + 1;
            *delimiter = 0; // Add a null terminator
            // Note that this null terminator can break the user ID
            // and the password without allocating other buffers.
            char *user_id = id_password;

            delimiter = strchr(password, '\n');
            *delimiter = 0; // Add a null terminator
            // Note that since we did not process it on the client side,
            // and since it is always typed by a user, there must be a
            // trailing new line. We just write a null terminator on this
            // place to terminate the password string.




            // The server need to reply a msg anyway, and this reply msg
            // contains only the header
            ph_send->magic1 = MAGIC_1;
            ph_send->magic2 = MAGIC_2;
            ph_send->payload_len = 0;
            ph_send->msg_id = 0;
            
            //printf("username: %s, password: %s\n",user_id,password );
            int login_success = check_id_password(user_id, password, cs);
            if (login_success > 0) {
                //printf("Login was successful\n");
                // This means the login is successful.

                ph_send->opcode = successful_login_ack;
                ph_send->token = generate_a_random_token();
                token = ph_send->token;
                //printf("token created for session:%u\n",token );

                cs = add_to_session_map(token, user_id);
                //printf("Before Assigning values to cs\n");
                strcpy(cs->client_id, user_id);
                //printf("The client_id is: %s\n",cs->client_id);
                cs->state = STATE_ONLINE;
                cs->token = ph_send->token;
                cs->last_time = time(NULL);  //USED TO BE right_now();
                lasttime = time(NULL);
                cs->client_addr = cli_addr;
                //printf("After Assigning values to cs\n");
                add_the_session_to_clientStruct(cs);

            } else {

                ph_send->opcode = failed_login_ack;
                ph_send->token = 0;
                printf("failed_login_sent\n");

            }

            sendto(sockfd, send_buffer, h_size, 0, 
                (struct sockaddr *) &cli_addr, sizeof(cli_addr));



        } else if (event == EVENT_POST) {
            if(cs->state == STATE_ONLINE){
                //printf("Entered EVENT POST\n");
            // TODO: Check the state of the client that sends this post msg,
            // i.e., check cs->state.

            // Now we assume it is ONLINE, because I do not want to ident
            // the following code in another layer.
            session * cs2 = find_the_session_by_token(cs->token);
            //for each target session subscribed to this publisher 
            cs = find_the_session_by_token(ph_recv->token);
            writeFile(cs, cs->client_id, recv_buffer+h_size, ph_recv->payload_len);
            //printf("%s's token is %d\n",cs->client_id, ph_recv->token );
            //printf("Wrote %s.txt 1st\n",cs->client_id );
            bool sent = false;

            for(int i =0; i< 3; i++)
            {

                    if(!strcmp(clients[i].clientID,cs->client_id)){
                        //printf("%s's subscriber: %s\n",clients[i].clientID,clients[i].subscriber);
                        char *text2 = recv_buffer + h_size;
                        char *payload = send_buffer + h_size;
                        char str[100];
                        
                        char text[ph_recv->payload_len];
                        strcpy(text,text2);
                        text[ph_recv->payload_len]='\0';
                        strcpy(str,cs->client_id);
                        strcat(str,tag);
                        strcat(str,text);

                        // This formatting the "<client_a>some_text" in the payload
                        // of the forward msg, and hence, the client does not need
                        // to format it, i.e., the client can just print it out.
                        snprintf(payload, sizeof(send_buffer) - h_size, "<%s>%s",
                            cs->client_id, text);
                        
                        int m = strlen(payload);
                        session * target;
                        // "target" is the session structure of the target client.
                        //printf("clients[i].subscriber: %s\n",clients[i].subscriber);
                            if(clients[i].subscriber[0]!='\0'){
                                for(int j=0; j<3;j++){
                                    if(!strcmp(clients[i].subscriber,clients[j].clientID)){
                                        //printf("sending post\n");
                                        target = &clients[j].sess;
                                        if(target->state == STATE_ONLINE){
                                        int m = strlen(str);
                                        target->state = STATE_ONLINE;
                                        ph_send->magic1 = MAGIC_1;
                                        ph_send->magic2 = MAGIC_2;
                                        ph_send->opcode = forward;
                                        ph_send->payload_len = m;
                                        ph_send->token = target->token;
                                        ph_send->msg_id = 0; // Note that I didn't use msg_id here.
                                        memcpy(send_buffer + h_size, str, m);
                                        sendto(sockfd, send_buffer, h_size+m, 0, 
                                            (struct sockaddr *) &target->client_addr, 
                                            sizeof(target->client_addr));
                                        sent = true;


                                        

                                        }
                                    }
                                }
                            
                            writeFile(cs, (char *)clients[i].subscriber, text, strlen(text));
                            }
                    }
            }
            if(sent == true){
                ph_send->opcode = push_ack;
            ph_send->magic1 = MAGIC_1;
            ph_send->magic2 = MAGIC_2;
            ph_send->payload_len = 0;
            ph_send->msg_id = 0;
            ph_send->token = token;

            sendto(sockfd, send_buffer, h_size, 0, 
                (struct sockaddr *) &cli_addr, sizeof(cli_addr));
            }
            ph_send->opcode = post_ack;
            ph_send->magic1 = MAGIC_1;
            ph_send->magic2 = MAGIC_2;
            ph_send->payload_len = 0;
            ph_send->msg_id = 0;
            ph_send->token = token;

            sendto(sockfd, send_buffer, h_size, 0, 
                (struct sockaddr *) &cli_addr, sizeof(cli_addr));


            // TODO: send back the post ack to this publisher.

            // TODO: put the posted text line into a global list.




            // TODO: process other events*/
        }
        }else if (event == EVENT_SUBSCRIBE){
            cs = find_the_session_by_token(ph_recv->token);
            if(cs->state == STATE_ONLINE){
            char name[ph_recv->payload_len];
            strcpy(name, recv_buffer+h_size);
            name[ph_recv->payload_len-1] = '\0';
            //printf("%s\n",name );
            if(strcmp(name,cs->client_id)){
            for(int i =0; i < 3; i++){
                if(!strcmp(clients[i].clientID,name))
                {
                        //printf("name: %s\n",name );
                        //printf("clients[i].clientID: %s\n",clients[i].clientID );
                        strcpy(clients[i].subscriber, cs->client_id);
                        ph_send->magic1 = MAGIC_1;
                        ph_send->magic2 = MAGIC_2;
                        ph_send->opcode = successful_subscribe_ack;
                        ph_send->payload_len = 0;
                        ph_send->token = cs->token;
                        ph_send->msg_id = 0; // Note that I didn't use msg_id here.
                        sendto(sockfd, send_buffer, h_size, 0, 
                            (struct sockaddr *) &cs->client_addr, 
                            sizeof(cs->client_addr));
                        
                }
            }
            }
            else{
            ph_send->magic1 = MAGIC_1;
            ph_send->magic2 = MAGIC_2;
            ph_send->opcode = failed_subscribe_ack;
            ph_send->payload_len = 0;
            ph_send->token = cs->token;
            ph_send->msg_id = 0; // Note that I didn't use msg_id here.
            sendto(sockfd, send_buffer, h_size, 0, 
                (struct sockaddr *) &cs->client_addr, 
                sizeof(cs->client_addr));
            }
            
        }
        }else if(event == EVENT_UNSUBSCRIBE){
            cs = find_the_session_by_token(ph_recv->token);
            if(cs->state == STATE_ONLINE){

            int j =0;
            char name[ph_recv->payload_len];
            
            strcpy(name, recv_buffer+h_size);
            name[ph_recv->payload_len-1] = '\0';
            if(strcmp(name,cs->client_id)){
                for(int i =0; i < 3; i++){
                    //printf("clients[]:%s, name: %s \n",clients[i].clientID,name );
                    if(!strcmp(clients[i].clientID,name))
                    {
                            //clients[i].subscriber=name;
                            clients[i].subscriber[0]='\0';
                            ph_send->magic1 = MAGIC_1;
                            ph_send->magic2 = MAGIC_2;
                            ph_send->opcode = successful_unsubscribe_ack;
                            ph_send->payload_len = 0;
                            ph_send->token = cs->token;
                            ph_send->msg_id = 0; // Note that I didn't use msg_id here.
                            sendto(sockfd, send_buffer, h_size, 0, 
                                (struct sockaddr *) &cs->client_addr, 
                                sizeof(cs->client_addr));
                            break;
                            
                    }
                }
            }
            else{
            ph_send->magic1 = MAGIC_1;
            ph_send->magic2 = MAGIC_2;
            ph_send->opcode = failed_unsubscribe_ack;
            ph_send->payload_len = 0;
            ph_send->token = cs->token;
            ph_send->msg_id = 0; // Note that I didn't use msg_id here.
            sendto(sockfd, send_buffer, h_size, 0, 
                (struct sockaddr *) &cs->client_addr, 
                sizeof(cs->client_addr));
            }
            

           } 

        }else if(event == EVENT_FORWARD_ACK){
            printf("forward_ack\n");
            
        }else if(event == EVENT_RETRIEVE){
            //printf("EVENT_RETRIEVE\n");
            cs = find_the_session_by_token(ph_recv->token);
            if(cs->state == STATE_ONLINE){
            N n;
            int size =0;
            char feed[100];
            char * ptr;
            char c;
            int count;
            char text[1];
            strcpy(n.byte,recv_buffer+h_size);
            char str[36];
            size = atoi(n.byte);
            //printf("size =%d\n",size );
            strcpy(str,cs->client_id);
            strcat(str,".txt");
            
            ifstream myfile(ptr);
            
            int i = 0;
            //find the length of the files
            reverse_file(str,"Retrieve.txt");
            reverse_file_lines("Retrieve.txt","toRetrieve.txt");
            FILE * file = fopen("toRetrieve.txt", "ab+");
            fseek(file, 0 , SEEK_SET);
            ph_send->magic1 = MAGIC_1;
            ph_send->magic2 = MAGIC_2;
            ph_send->opcode = retrieve_ack;
            ph_send->msg_id = 0;
            sendto(sockfd, send_buffer, h_size, 0, 
                (struct sockaddr *) &cs->client_addr, 
                sizeof(cs->client_addr));
            





            while( fgets(feed, 32, file)!=0 && i < size){
                if(feed[0]=='\n')
                    fgets(feed,32,file);
            //printf("while loop: %s\n",feed );
            puts(feed);
            //printf("after puts while loop %s\n",feed );
            ph_send->magic1 = MAGIC_1;
            ph_send->magic2 = MAGIC_2;
            ph_send->opcode = retrieve_ack;
            //feed[strlen(feed)]='\0';
            //ph_send->payload_len = strlen(feed)-1;
            if(i < size-1){feed[strlen(feed)]='\0';
            ph_send->payload_len = strlen(feed)-1;}
            else{
                feed[strlen(feed)+1]='\0';
                //printf("feed:%s\n",feed );
                ph_send->payload_len = strlen(feed)+1;
            }
            ph_send->msg_id = 0; // Note that I didn't use msg_id here.
            memcpy(send_buffer + h_size, feed, ph_send->payload_len);
            sendto(sockfd, send_buffer, h_size+ph_send->payload_len, 0, 
                (struct sockaddr *) &cs->client_addr, 
                sizeof(cs->client_addr));
            if(i<size-1){
            ph_send->magic1 = MAGIC_1;
            ph_send->magic2 = MAGIC_2;
            ph_send->opcode = retrieve_ack;
            ph_send->msg_id = 0;
            sendto(sockfd, send_buffer, h_size, 0, 
                (struct sockaddr *) &cs->client_addr, 
                sizeof(cs->client_addr));
        }
            //sleep(1);
            i++;
            }
            fclose(file);
            remove("toRetrieve.txt");
            remove("Retrieve.txt");
            
            
            /*if(size > 1){
            
            puts(feed);
            printf("inside if: %s\n",feed);
            ph_send->opcode = end_of_retrieve_ack;
            memcpy(send_buffer + h_size, feed, strlen(feed)-1);
            sendto(sockfd, send_buffer, h_size+ph_send->payload_len, 0, 
                (struct sockaddr *) &cs->client_addr, 
                sizeof(cs->client_addr));
            }*/
            //printf("Exiting retrieve\n");

        }
            
        }else if(event == EVENT_LOGOUT){
            cs = find_the_session_by_token(ph_recv->token);
            if(cs->state == STATE_ONLINE){

                for(int i = 0; i < 3; i++){
                    if(!strcmp(clients[i].clientID,cs->client_id)){
                        ph_send->magic1 = MAGIC_1;
                        ph_send->magic2 = MAGIC_2;
                        ph_send->payload_len = 0;
                        ph_send->msg_id = 0;
                        ph_send->opcode = logout_ack;
                        ph_send->token = token;
                        sendto(sockfd, send_buffer, h_size, 0, 
                        (struct sockaddr *) &cli_addr, sizeof(cli_addr));
                    }
                }
            
            cs->state = STATE_OFFLINE;
            //sessionsMap.erase(token);
        }
        }else if(event == EVENT_INVALID){
            
        }else if (event == EVENT_SESSION_RESET){
            cs = find_the_session_by_token(ph_recv->token);
            if(cs->state == STATE_ONLINE){

                for(int i = 0; i < 3; i++){
                    if(!strcmp(clients[i].clientID,cs->client_id)){
                        ph_send->magic1 = MAGIC_1;
                        ph_send->magic2 = MAGIC_2;
                        ph_send->payload_len = 0;
                        ph_send->msg_id = 0;
                        ph_send->opcode = session_reset;
                        ph_send->token = token;
                        sendto(sockfd, send_buffer, h_size, 0, 
                        (struct sockaddr *) &cli_addr, sizeof(cli_addr));
                    }
                }
            
            cs->state = STATE_OFFLINE;
            //sessionsMap.erase(cs->token);
        }
    }
        else if(event == EVENT_SERVER_RESET){
            for(int i = 0; i < 3; i++){
                        if(clients[i].sess.state == STATE_ONLINE){
                        ph_send->magic1 = MAGIC_1;
                        ph_send->magic2 = MAGIC_2;
                        ph_send->payload_len = 0;
                        ph_send->msg_id = 0;
                        ph_send->opcode = 0x02;
                        ph_send->token = clients[i].sess.token;
                        sendto(sockfd, send_buffer, h_size, 0, 
                        (struct sockaddr *) &clients[i].sess.client_addr, sizeof(cli_addr));
                        clients[i].sess.state = STATE_OFFLINE;
                    }

                }
            
            cs->state = STATE_OFFLINE;


        }

        time_t current_time = time(NULL);
        //printf("After current_session->last_time\n");
        for(int i = 0; i< 3; i++){
            //printf("client_a time: %ld\n",client_a.sess->last_time);
            if(clients[i].sess.state == STATE_ONLINE && difftime(current_time, clients[i].sess.last_time)>60)
            {
                //printf("difftime: %lf\n",difftime(current_time, clients[i].sess.last_time));

            ph_send->magic1 = MAGIC_1;
            ph_send->magic2 = MAGIC_2;
            ph_send->payload_len = 0;
            ph_send->msg_id = 0;
            ph_send->opcode = logout_ack;
            ph_send->token = token;
            printf("sending timeout to %s\n",clients[i].clientID);
            sendto(sockfd, send_buffer, h_size, 0, 
                (struct sockaddr *) &clients[i].sess.client_addr, sizeof(cli_addr));
            clients[i].sess.state = STATE_OFFLINE;

            }
            else if(!strcmp(clients[i].clientID,cs->client_id)){
                clients[i].sess.last_time=time(NULL);
            }
        }
        /*for(int i = 0; i< 3; i++){
            if(!strcmp(clients[i].clientID,cs->client_id)){
                clients[i].sess.last_time=cs->last_time;
            }
        }*/
        // Now you may check the time of clients, i.e., scan all sessions. 
        // For each session, if the current time has passed 5 minutes plus 
        // the last time of the session, the session expires.
        // TODO: check session liveliness
        


    } // This is the end of the while loop

    return 0;
} // This is the end of main()