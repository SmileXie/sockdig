use std::env;
use std::fs;
use simplelog;
use log;
use std::process::exit;
use std::io::Result;

use netlink_packet_sock_diag::{
    constants::*,
    inet::{ExtensionFlags, InetRequest, InetResponse, SocketId, StateFlags},
    NetlinkHeader, NetlinkMessage, NetlinkPayload, SockDiagMessage,
};
use netlink_sys::{protocols::NETLINK_SOCK_DIAG, Socket, SocketAddr};

struct DigResult {
    resp: InetResponse,
}

impl DigResult {
    fn summary(&self) {
        println!("{:>16}{:>16}", 
            self.resp.header.socket_id.source_address, 
            self.resp.header.socket_id.destination_address, 
        )
    }
} 

fn print_help() {
    println!("Sockdig Help:");
}

fn sock_init() -> Result<Socket> {
    let mut sock =  Socket::new(NETLINK_SOCK_DIAG)?;
    let _addr = sock.bind_auto()?;
    sock.connect(&SocketAddr::new(0, 0));

    Ok(sock)
}

fn main() {

    let args: Vec<String> = env::args().collect();

    let mut debug_mode = false;
    if args.len() == 2 {
        if args[1] == "--help" || args[1] == "-h" {
            print_help();            
            exit(0);
        } else if args[1] == "--debug" || args[1] == "-d" {
            debug_mode = true;
        } else {
            print_help();
            exit(0);
        }
    } else if args.len() > 2 {
        print_help();
        exit(0);
    }

    if debug_mode {
        match fs::File::create(".sockdig.log") {
            Ok(fd) => {
                simplelog::WriteLogger::init(simplelog::LevelFilter::Debug, simplelog::Config::default(), fd).unwrap();
            },
            Err(io_error) => {
                println!("Fail to create log file {}, {}", ".cdls.log", io_error);
                exit(1);
            },
        };  
    }

    let sock = match sock_init() {
        Ok(sock) => sock,
        Err(e) => {
            log::error!("Fail to init socket, {}", e);
            exit(1);
        }
    };

    let mut packet = NetlinkMessage {
        header: NetlinkHeader {
            flags: NLM_F_REQUEST | NLM_F_DUMP,
            ..Default::default()
        },
        payload: SockDiagMessage::InetRequest(InetRequest {
            family: AF_INET,
            protocol: IPPROTO_TCP,
            extensions: ExtensionFlags::empty(),
            states: StateFlags::all(),
            socket_id: SocketId::new_v4(),
        })
        .into(),
    };

    packet.finalize();

    let mut buf = vec![0; packet.header.length as usize];

    // Before calling serialize, it is important to check that the buffer in which
    // we're emitting is big enough for the packet, other `serialize()` panics.
    assert_eq!(buf.len(), packet.buffer_len());

    packet.serialize(&mut buf[..]);

    log::debug!(">>> {:?}", packet);
    if let Err(e) = sock.send(&buf[..], 0) {
        log::debug!("SEND ERROR {}", e);
        return;
    }

    let mut receive_buffer = vec![0; 4096];
    let mut offset = 0;
    let mut rsts: Vec<DigResult> = vec![];
    let mut done: bool = false;
    loop {
        if done {
            break;
        }

        let mut recv_size = 0;
        match sock.recv(&mut &mut receive_buffer[..], 0) {
            Ok(size) => {recv_size = size;},
            Err(e) => {
                log::error!("Recv failed. {}", e);
                break;
            }
        }

        loop {
            let bytes = &receive_buffer[offset..];
            let rx_packet = <NetlinkMessage<SockDiagMessage>>::deserialize(bytes).unwrap();
            log::debug!("<<< rx_packet: {:?}", rx_packet);

            match rx_packet.payload {
                NetlinkPayload::Noop | NetlinkPayload::Ack(_) => {}
                NetlinkPayload::InnerMessage(SockDiagMessage::InetResponse(response)) => {
                    rsts.push(DigResult{resp: (*response).clone()});
                    log::debug!("<<<<<<< Response: {:#?}", response);
                }
                NetlinkPayload::Done => {
                    log::debug!("<<<<<<< Done!");
                    done = true;
                    break;
                }
                _ => {
                    log::debug!("Invalid payload.");
                    done = true;
                    break;
                }
            }

            offset += rx_packet.header.length as usize;
            if offset == recv_size || rx_packet.header.length == 0 {
                offset = 0;
                break;
            }
        }
    
    }

    for rst in rsts {
        rst.summary();
    }
}