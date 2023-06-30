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
    inet,
    inet::{ExtensionFlags, InetRequest, InetResponse, SocketId},
    unix,
    unix::{UnixRequest, UnixResponse, ShowFlags},
    NetlinkHeader, NetlinkMessage, NetlinkPayload, SockDiagMessage,
};
use netlink_sys::{protocols::NETLINK_SOCK_DIAG, Socket, SocketAddr};
use structopt::StructOpt;


enum RespEntry {
    TCP(InetResponse),
    UDP(InetResponse),
    UNIX(UnixResponse),
    NONE,
}

enum SockType {
    TcpV4,
    UdpV4,
    TcpV6,
    UdpV6,
    Unix
}

#[derive(StructOpt, Debug)]
#[structopt(name = "basic")]
struct RunMode {
    #[structopt(long = "debug")]
    debug: bool,
    #[structopt(short = "d", long = "detail")]
    detail: bool,
    #[structopt(short = "p", long = "pid", default_value ="0")]
    pid: i32,
}

impl RunMode {

    fn display(& self) {
        log::debug!("args: {:?}", self);
    }
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

    fn detail(&self, pid: i32) {
        let mut num = 0;
        for resp_entry in &self.resp {
            let mut pid_match = false;
            match resp_entry {
                RespEntry::TCP(r) | RespEntry::UDP(r) => {
                    
                    let src: String = format!("{}:{}",
                            r.header.socket_id.source_address, 
                            r.header.socket_id.source_port);
                    let dst: String = format!("{}:{}",
                            r.header.socket_id.destination_address, 
                            r.header.socket_id.destination_port);
                    let proc_stats = self.inode_to_pid_map.get(&(r.header.inode as u64));
                    let mut proc_stats_str = String::new();                    
                    match proc_stats {
                        Some(states) => {                            
                            for stat in states {
                                let a_proc_str = format!("{}/{},", stat.pid, stat.comm);
                                proc_stats_str.push_str(&a_proc_str);
                                if pid == stat.pid {
                                    pid_match = true;
                                }
                            }
                            if pid != 0 && !pid_match { // no pid match, skip this entry
                                continue;
                            }    
                        },
                        None => {
                            if pid != 0 {
                                continue;
                            }
                        }
                    }
                    println!("Entry {}", num);
                    num += 1;
                    println!("\tProtocol: {}", self.get_protocol_str(resp_entry));
                    println!("\tState: {}", self.state_str(r.header.state, resp_entry));
                    println!("\tSource: {}", src);
                    println!("\tDestination: {}", dst);
                    println!("\tInode: {}", r.header.inode);
                    println!("\tAccessing Processes: {}", proc_stats_str);
                },
                RespEntry::UNIX(r) => {
                    
                    let src: String = format!("*:{}", r.header.inode);
                    let dst_inode: String = match r.peer() {
                        Some(p) => p.to_string(),
                        None => "*".to_string()
                    };
                    let dst: String = format!("*:{}", dst_inode);
                    let proc_stats = self.inode_to_pid_map.get(&(r.header.inode as u64));
                    let mut proc_stats_str = String::new();
                    match proc_stats {
                        Some(states) => {                            
                            for stat in states {
                                let a_proc_str = format!("{}/{},", stat.pid, stat.comm);
                                proc_stats_str.push_str(&a_proc_str);
                                if pid == stat.pid {
                                    pid_match = true;
                                }
                            }
                            if pid != 0 && !pid_match { // no pid match, skip this entry
                                continue;
                            }    
                        },
                        None => {
                            if pid != 0 {
                                continue;
                            }
                        }
                    }
                    println!("Entry {}", num);
                    num += 1;
                    println!("\tProtocol: {}", self.get_protocol_str(resp_entry));
                    println!("\tState: {}", self.state_str(r.header.state, resp_entry));
                    println!("\tSource: {}", src);
                    println!("\tDestination: {}", dst);
                    println!("\tInode: {}", r.header.inode);
                    println!("\tAccessing Processes: {}", proc_stats_str);
                },
                _ => {}
            }
        }
    }

    fn summary(&self, pid: i32) {
        println!("{:<9}{:<16}{:<24}{:<24}{:<8}{:<24}", 
            "Protocol", "State", "Source", "Destination", 
            "Inode", "Processes");
        
        for resp_entry in &self.resp {
            let mut pid_match = false;
            match resp_entry {
                RespEntry::TCP(r) | RespEntry::UDP(r) => {
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
                                if pid == stat.pid {
                                    pid_match = true;
                                }
                            }
                            if pid != 0 && !pid_match { // no pid match, skip this entry
                                continue;
                            }    
                
                            println!("{:<9}{:<16}{:<24}{:<24}{:<8}{:<24}", 
                                self.get_protocol_str(resp_entry),
                                self.state_str(r.header.state, resp_entry), src, dst, 
                                r.header.inode, proc_stats_str);
                            
                        },
                        None => {      
                            if pid != 0 {
                                continue;
                            }     
                            println!("{:<9}{:<16}{:<24}{:<24}{:<8}", 
                                self.get_protocol_str(resp_entry),
                                self.state_str(r.header.state, resp_entry), src, dst, 
                                r.header.inode);
                        }
                    }

                },
                RespEntry::UNIX(r) => {
                    let src: String = format!("*:{}", r.header.inode);
                    let dst_inode: String = match r.peer() {
                        Some(p) => p.to_string(),
                        None => "*".to_string()
                    };
                    let dst: String = format!("*:{}", dst_inode);

                    let proc_stats = self.inode_to_pid_map.get(&(r.header.inode as u64));
                    
                    match proc_stats {
                        Some(states) => {
                            let mut proc_stats_str = String::new();
                            for stat in states {
                                let a_proc_str = format!("{}/{},", stat.pid, stat.comm);
                                proc_stats_str.push_str(&a_proc_str);
                                if pid == stat.pid {
                                    pid_match = true;
                                }
                            }
                            if pid != 0 && !pid_match { // no pid match, skip this entry
                                continue;
                            }
                
                            println!("{:<9}{:<16}{:<24}{:<24}{:<8}{:<24}", 
                                self.get_protocol_str(resp_entry),
                                self.state_str(r.header.state, resp_entry), src, dst, 
                                r.header.inode, proc_stats_str);
                            
                        },
                        None => {
                            if pid != 0 {
                                continue;
                            }
                            println!("{:<9}{:<16}{:<24}{:<24}{:<8}", 
                                self.get_protocol_str(resp_entry),
                                self.state_str(r.header.state, resp_entry), src, dst, 
                                r.header.inode);
                        }
                    }
                }
                _ => {}
            }

        }
    }        

    fn state_str(&self, state: u8, resp_entry: &RespEntry) -> &str {
        return match resp_entry {
            RespEntry::TCP(_r) => match state {
                TCP_ESTABLISHED => "ESTABLISHED",
                TCP_SYN_SENT => "SYN_SENT",
                TCP_SYN_RECV => "SYN_RECV",
                TCP_FIN_WAIT1 => "FIN_WAIT1",
                TCP_FIN_WAIT2 => "FIN_WAIT2",
                TCP_TIME_WAIT => "TIME_WAIT",
                TCP_CLOSE => "CLOSE",
                TCP_CLOSE_WAIT => "CLOSE_WAIT",
                TCP_LAST_ACK => "LAST_ACK",
                TCP_LISTEN => "LISTEN",
                TCP_CLOSING => "CLOSING",
                _ => "TCP_UNKNOWN"
            },
            RespEntry::UNIX(_r) => match state {
                TCP_ESTABLISHED => "ESTABLISHED",
                TCP_SYN_SENT => "SYN_SENT",
                TCP_SYN_RECV => "SYN_RECV",
                TCP_FIN_WAIT1 => "FIN_WAIT1",
                TCP_FIN_WAIT2 => "FIN_WAIT2",
                TCP_TIME_WAIT => "TIME_WAIT",
                TCP_CLOSE => "CLOSE",
                TCP_CLOSE_WAIT => "CLOSE_WAIT",
                TCP_LAST_ACK => "LAST_ACK",
                TCP_LISTEN => "LISTEN",
                TCP_CLOSING => "CLOSING",
                _ => "UNIX_UNKNOWN"
            },
            RespEntry::UDP(_r) => match state {
                TCP_ESTABLISHED => "ESTABLISHED",
                TCP_CLOSE => "UNCONNECT",
                TCP_LISTEN => "LISTEN",
                TCP_CLOSING => "CLOSING",
                _ => "UDP_UNKNOWN"
            },
            _ => "UNKNOWN"
        }        
    }

    fn get_protocol_str(&self, resp_entry: &RespEntry) -> &str {
        return match resp_entry {
            RespEntry::TCP(_r) => "TCP",
            RespEntry::UDP(_r) => "UDP",
            RespEntry::UNIX(_r) => "UNIX",
            _ => "UNKNOWN"
        }
    }
} 

fn sock_init() -> io::Result<Socket> {
    let mut sock =  Socket::new(NETLINK_SOCK_DIAG)?;
    let _addr = sock.bind_auto()?;
    sock.connect(&SocketAddr::new(0, 0))?;

    Ok(sock)
}

fn query_netlink_for_unix(sock: &Socket, rsts: &mut DigResult) 
        -> Result<u32, io::Error> {
            
    let mut packet = NetlinkMessage {
        header: NetlinkHeader {
            flags: NLM_F_REQUEST | NLM_F_DUMP,
            ..Default::default()
        },
        payload: SockDiagMessage::UnixRequest(UnixRequest {
            state_flags: unix::StateFlags::all(),
            inode: 0,
            show_flags: ShowFlags::all(),
            cookie: [0; 8]
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
                NetlinkPayload::InnerMessage(SockDiagMessage::UnixResponse(response)) => {
                    rsts.resp.push(RespEntry::UNIX((*response).clone()));
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

fn query_netlink_for_tcp_udp(sock: &Socket, rsts: &mut DigResult, sock_type: SockType) 
        -> Result<u32, io::Error> {

    let mut packet = NetlinkMessage {
        header: NetlinkHeader {
            flags: NLM_F_REQUEST | NLM_F_DUMP,
            ..Default::default()
        },
        payload: SockDiagMessage::InetRequest(InetRequest {
            family: AF_INET,
            protocol: match sock_type {
                    SockType::TcpV4 => IPPROTO_TCP,
                    SockType::UdpV4 => IPPROTO_UDP,
                    _ => IPPROTO_NONE,
                },
            extensions: ExtensionFlags::empty(),
            states: inet::StateFlags::all(),
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
                    rsts.resp.push(
                        match sock_type {
                            SockType::TcpV4 => RespEntry::TCP((*response).clone()),
                            SockType::UdpV4 => RespEntry::UDP((*response).clone()),
                            _ => RespEntry::NONE,
                        }
                    );
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

fn args_to_runmode() -> RunMode {

    let mut run_mode = RunMode::from_args();
   
    /* 
    let args: Vec<String> = env::args().collect();

    let mut run_mode = RunMode {debug: false, detail: false};
    if args.len() == 2 {
        if args[1] == "--help" || args[1] == "-h" {
            print_help();            
            exit(0);
        } else if args[1] == "--debug" {
            run_mode.debug = true;
        } else if args[1] == "--detail" || args[1] == "-d" {
            run_mode.detail = true;
        } else {
            print_help();
            exit(0);
        }
    } else if args.len() > 2 {
        print_help();
        exit(0);
    }
    */

    return run_mode;
}

fn main() {
  

    let run_mode: RunMode = args_to_runmode();

    if run_mode.debug {
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

    run_mode.display();

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

    query_netlink_for_tcp_udp(&sock, &mut rsts, SockType::TcpV4);
    query_netlink_for_tcp_udp(&sock, &mut rsts, SockType::UdpV4);
    query_netlink_for_unix(&sock, &mut rsts);

    rsts.resolve_procfs();
    if run_mode.detail {
        rsts.detail(run_mode.pid);
    } else {
        rsts.summary(run_mode.pid);
    }
}

/*
    Reference:
    https://github.com/eminence/procfs/blob/master/examples/netstat.rs
    https://man7.org/linux/man-pages/man7/sock_diag.7.html
    https://github.com/little-dude/netlink/blob/master/netlink-packet-sock-diag/examples/dump_ipv4.rs

    TODO:
    display interface of listening socket, eg. lo in 127.0.0.53%lo:domain  
    ipv6 socket display

 */
