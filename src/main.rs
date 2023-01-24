use std::env;
use std::fs;
use std::path;
use procfs::ProcError;
use simplelog;
use log;
use std::process::exit;
use std::io;
use std::collections::HashMap;
use procfs::process::{FDTarget, Stat};
use netlink_packet_sock_diag::{
    constants::*,
    inet::{ExtensionFlags, InetRequest, InetResponse, SocketId, StateFlags},
    unix::{UnixResponse},
    NetlinkHeader, NetlinkMessage, NetlinkPayload, SockDiagMessage,
};
use netlink_sys::{protocols::NETLINK_SOCK_DIAG, Socket, SocketAddr};

enum RespEntry {
    TCP(InetResponse),
    UDP(InetResponse),
    UNIX(UnixResponse)
}

struct DigResult {
    resp: Vec<RespEntry>,
    inode_to_pid_map: HashMap<u64, Vec<Stat>>,
}

impl DigResult {
    
    fn resolve_procfs(&mut self) -> Result<u32, ProcError> {
        let all_procs = procfs::process::all_processes()?;

        // build up a map between socket inodes and processes:
        for p in all_procs {
            if let Err(e) = p {
                log::warn!("error in process info of procfs. {}", e);
                continue;
            }

            let process = p.unwrap();
            if let (Ok(stat), Ok(fds)) = (process.stat(), process.fd()) {
                for fd in fds {
                    if let FDTarget::Socket(inode) = fd.unwrap().target {
                        self.inode_to_pid_map.entry(inode)
                            // If there's no entry for key inode, create a new Vec and return a mutable ref to it
                            .or_default()
                            // and insert the item onto the Vec
                            .push(stat.clone()); 
                        // refer to https://stackoverflow.com/questions/51584729/how-can-i-store-multiple-elements-in-a-rust-hashmap-for-the-same-key
                    }
                }
            }
        }

        return Ok(0);
    }

    fn summary(&self) {
        println!("{:<20}{:<24}{:<24}{:<8}{:<24}", 
            "State", "Source", "Destination", 
            "Inode", "Processes");
        
        for resp_entry in &self.resp {
            match resp_entry {
                RespEntry::TCP(r) => {
                    let src: String = format!("{}:{}",
                            r.header.socket_id.source_address, 
                            r.header.socket_id.source_port);
                    let dst: String = format!("{}:{}",
                            r.header.socket_id.destination_address, 
                            r.header.socket_id.destination_port);

                    let proc_stats = self.inode_to_pid_map.get(&(r.header.inode as u64));
                    
                    match proc_stats {
                        Some(states) => {
                            let mut proc_stats_str = String::new();
                            for stat in states {
                                let a_proc_str = format!("{}/{},", stat.pid, stat.comm);
                                proc_stats_str.push_str(&a_proc_str);
                            }
                
                            println!("{:<20}{:<24}{:<24}{:<8}{:<24}", 
                                self.tcp_state(r.header.state), src, dst, 
                                r.header.inode, proc_stats_str);
                            
                        },
                        None => {           
                                println!("{:<20}{:<24}{:<24}{:<8}", 
                                    self.tcp_state(r.header.state), src, dst, 
                                    r.header.inode);
                        }
                    }

                },
                _ => {}
            }

        }
    }        

    fn tcp_state(&self, state: u8) -> &str {
        let ret = match state {
            TCP_ESTABLISHED => "TCP_ESTABLISHED",
            TCP_SYN_SENT => "TCP_SYN_SENT",
            TCP_SYN_RECV => "TCP_SYN_RECV",
            TCP_FIN_WAIT1 => "TCP_FIN_WAIT1",
            TCP_FIN_WAIT2 => "TCP_FIN_WAIT2",
            TCP_TIME_WAIT => "TCP_TIME_WAIT",
            TCP_CLOSE => "TCP_CLOSE",
            TCP_CLOSE_WAIT => "TCP_CLOSE_WAIT",
            TCP_LAST_ACK => "TCP_LAST_ACK",
            TCP_LISTEN => "TCP_LISTEN",
            TCP_CLOSING => "TCP_CLOSING",
            _ => "TCP_UNKNOWN"
        };

        return ret;
    }
} 

fn print_help() {
    println!("Sockdig Help:");
}

fn sock_init() -> io::Result<Socket> {
    let mut sock =  Socket::new(NETLINK_SOCK_DIAG)?;
    let _addr = sock.bind_auto()?;
    sock.connect(&SocketAddr::new(0, 0))?;

    Ok(sock)
}

fn query_netlink_for_tcp(sock: Socket, rsts: &mut DigResult) -> Result<u32, io::Error> {

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
        return Err(e);
    }

    let mut receive_buffer = vec![0; 4096];
    let mut offset = 0;
    let mut done: bool = false;
    loop {
        if done {
            break;
        }

        let recv_size;
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
                    rsts.resp.push(RespEntry::TCP((*response).clone()));
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

    return Ok(0);
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

    let mut rsts: DigResult = DigResult {
        resp: Vec::new(),
        inode_to_pid_map: HashMap::new()
    };

    query_netlink_for_tcp(sock, &mut rsts);

    rsts.resolve_procfs();
    rsts.summary();
}

/*
    reference:
    https://github.com/eminence/procfs/blob/master/examples/netstat.rs
    https://man7.org/linux/man-pages/man7/sock_diag.7.html
 */
