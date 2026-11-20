use std::{
    fs, io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

use crate::event::{Endpoint, SCHEMA_VERSION, clock_ns};

pub const HOOK: &str = "ctnetlink:conntrack";
const GROUP_MASK: u32 = 0b111; // NFNLGRP_CONNTRACK_NEW, UPDATE, DESTROY
const MAX_DATAGRAM: usize = 65_536;
const READS_PER_POLL: usize = 16;
const RECORDS_PER_SECOND: u64 = 512;
const CT_NEW: u16 = 0x100;
const CT_DELETE: u16 = 0x102;
const IPS_SRC_NAT: u32 = 1 << 4;
const IPS_DST_NAT: u32 = 1 << 5;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct Tuple {
    pub src: Endpoint,
    pub dst: Endpoint,
}

impl Tuple {
    pub fn reverse(self) -> Self {
        Self {
            src: self.dst,
            dst: self.src,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Notice {
    New,
    Update,
    Destroy,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct NatEvent {
    pub schema_version: u8,
    pub record: String,
    pub hook: String,
    pub receipt_monotonic_ns: u64,
    pub conntrack_netns_inum: u32,
    pub conntrack_id: Option<u32>,
    pub original_zone: u16,
    pub reply_zone: u16,
    pub original: Tuple,
    pub reply: Tuple,
    pub translated: Tuple,
    pub source_nat: bool,
    pub destination_nat: bool,
    notice: Notice,
}

impl NatEvent {
    pub fn is_new(&self) -> bool {
        self.notice == Notice::New
    }
}
#[derive(Default, Serialize)]
pub struct Stats {
    pub received: u64,
    pub overruns: u64,
    pub truncated_datagrams: u64,
    pub decode_errors: u64,
    pub rate_limited: u64,
}

pub struct Listener {
    fd: OwnedFd,
    pub netns_inum: u32,
    pub stats: Stats,
    buffer: Box<[u8]>,
    window_second: u64,
    window_records: u64,
}

impl Listener {
    pub fn open() -> Result<Self> {
        if let Ok(setting) = fs::read_to_string("/proc/sys/net/netfilter/nf_conntrack_events") {
            ensure!(
                setting.trim() != "0",
                "conntrack events are disabled in this network namespace"
            );
        }
        let netns_inum = crate::netns::current_inode()?;
        // The nonblocking socket only subscribes to kernel multicast. It sends no messages.
        let fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                libc::NETLINK_NETFILTER,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error()).context("open netfilter netlink");
        }
        // Ownership of the successful socket descriptor transfers to OwnedFd.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        let buffer_bytes: libc::c_int = 256 * 1024;
        // setsockopt copies this integer during the call.
        if unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                (&raw const buffer_bytes).cast(),
                size_of_val(&buffer_bytes) as _,
            )
        } < 0
        {
            return Err(io::Error::last_os_error()).context("set conntrack receive buffer");
        }
        // sockaddr_nl permits an all-zero initial state, including its padding.
        let mut address: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        address.nl_family = libc::AF_NETLINK as _;
        address.nl_groups = GROUP_MASK;
        // bind reads the initialized address for the supplied length.
        if unsafe {
            libc::bind(
                fd.as_raw_fd(),
                (&raw const address).cast(),
                size_of_val(&address) as _,
            )
        } < 0
        {
            return Err(io::Error::last_os_error())
                .context("subscribe to conntrack events (requires CAP_NET_ADMIN and ctnetlink)");
        }
        Ok(Self {
            fd,
            netns_inum,
            stats: Stats::default(),
            buffer: vec![0; MAX_DATAGRAM].into_boxed_slice(),
            window_second: 0,
            window_records: 0,
        })
    }

    pub fn drain(&mut self, mut emit: impl FnMut(NatEvent) -> Result<()>) -> Result<()> {
        for _ in 0..READS_PER_POLL {
            // recvfrom initializes the sender address and at most buffer.len() bytes.
            let mut sender: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
            let mut len = size_of_val(&sender) as libc::socklen_t;
            let read = unsafe {
                libc::recvfrom(
                    self.fd.as_raw_fd(),
                    self.buffer.as_mut_ptr().cast(),
                    self.buffer.len(),
                    libc::MSG_TRUNC,
                    (&raw mut sender).cast(),
                    &raw mut len,
                )
            };
            if read < 0 {
                let error = io::Error::last_os_error();
                match error.raw_os_error() {
                    Some(libc::EAGAIN) => break,
                    Some(libc::EINTR) => continue,
                    Some(libc::ENOBUFS) => {
                        self.stats.overruns += 1;
                        continue;
                    }
                    _ => return Err(error).context("receive conntrack events"),
                }
            }
            if sender.nl_family != libc::AF_NETLINK as u16 || sender.nl_pid != 0 {
                continue;
            }
            let size = read as usize;
            if size > self.buffer.len() {
                self.stats.truncated_datagrams += 1;
                continue;
            }
            let timestamp = clock_ns(libc::CLOCK_MONOTONIC)?;
            let second = timestamp / 1_000_000_000;
            if self.window_second != second {
                self.window_second = second;
                self.window_records = 0;
            }
            let mut data = &self.buffer[..size];
            while !data.is_empty() {
                let Some(header) = data.get(..16) else {
                    self.stats.decode_errors += 1;
                    break;
                };
                let length = u32::from_ne_bytes(header[..4].try_into().unwrap()) as usize;
                let Some(payload) = take_aligned(&mut data, length, 16) else {
                    self.stats.decode_errors += 1;
                    break;
                };
                let kind = u16::from_ne_bytes(header[4..6].try_into().unwrap());
                let flags = u16::from_ne_bytes(header[6..8].try_into().unwrap());
                if kind == libc::NLMSG_OVERRUN as u16 || kind == libc::NLMSG_ERROR as u16 {
                    self.stats.overruns += 1;
                    continue;
                }
                match decode(kind, flags, payload, timestamp, self.netns_inum) {
                    Ok(Some(_)) if self.window_records >= RECORDS_PER_SECOND => {
                        self.stats.rate_limited += 1;
                    }
                    Ok(Some(event)) => {
                        self.window_records += 1;
                        emit(event)?;
                        self.stats.received += 1;
                    }
                    Ok(None) => {}
                    Err(_) => self.stats.decode_errors += 1,
                }
            }
        }
        Ok(())
    }
}

fn take_aligned<'a>(data: &mut &'a [u8], length: usize, header: usize) -> Option<&'a [u8]> {
    if length < header || length > data.len() {
        return None;
    }
    let aligned = length.next_multiple_of(4);
    if aligned > data.len() && length != data.len() {
        return None;
    }
    let body = &data[header..length];
    *data = &data[aligned.min(data.len())..];
    Some(body)
}

fn attrs<const N: usize>(mut data: &[u8]) -> Result<[Option<&[u8]>; N]> {
    let mut fields = [None; N];
    while !data.is_empty() {
        let header = data.get(..4).context("short netlink attribute")?;
        let length = u16::from_ne_bytes(header[..2].try_into().unwrap()) as usize;
        let kind = (u16::from_ne_bytes(header[2..4].try_into().unwrap()) & 0x3fff) as usize;
        let payload = take_aligned(&mut data, length, 4).context("invalid attribute length")?;
        if let Some(field) = fields.get_mut(kind) {
            ensure!(
                field.replace(payload).is_none(),
                "duplicate conntrack attribute {kind}"
            );
        }
    }
    Ok(fields)
}

fn scalar<const N: usize>(field: Option<&[u8]>) -> Result<[u8; N]> {
    field
        .and_then(|value| value.try_into().ok())
        .context("missing or invalid conntrack field")
}

fn tuple(data: &[u8], family: u8) -> Result<Option<(Tuple, Option<u16>)>> {
    let fields = attrs::<4>(data)?;
    let proto = attrs::<4>(fields[2].context("missing conntrack protocol")?)?;
    if scalar::<1>(proto[1])?[0] != libc::IPPROTO_TCP as u8 {
        return Ok(None);
    }
    let ip = attrs::<5>(fields[1].context("missing conntrack addresses")?)?;
    let (src, dst) = if family == libc::AF_INET as u8 {
        (
            IpAddr::V4(Ipv4Addr::from(scalar::<4>(ip[1])?)),
            IpAddr::V4(Ipv4Addr::from(scalar::<4>(ip[2])?)),
        )
    } else {
        (
            IpAddr::V6(Ipv6Addr::from(scalar::<16>(ip[3])?)),
            IpAddr::V6(Ipv6Addr::from(scalar::<16>(ip[4])?)),
        )
    };
    Ok(Some((
        Tuple {
            src: Endpoint {
                address: src,
                port: Some(u16::from_be_bytes(scalar(proto[2])?)),
            },
            dst: Endpoint {
                address: dst,
                port: Some(u16::from_be_bytes(scalar(proto[3])?)),
            },
        },
        fields[3]
            .map(|value| scalar(Some(value)).map(u16::from_be_bytes))
            .transpose()?,
    )))
}

fn decode(
    kind: u16,
    flags: u16,
    payload: &[u8],
    stamp: u64,
    namespace: u32,
) -> Result<Option<NatEvent>> {
    let notice = match kind {
        CT_NEW if flags & libc::NLM_F_CREATE as u16 != 0 => Notice::New,
        CT_NEW => Notice::Update,
        CT_DELETE => Notice::Destroy,
        _ => return Ok(None),
    };
    let header = payload.get(..4).context("missing nfnetlink header")?;
    let family = header[0];
    if header[1] != 0 || (family != libc::AF_INET as u8 && family != libc::AF_INET6 as u8) {
        return Ok(None);
    }
    // nfnetlink_conntrack.h: ORIG=1, REPLY=2, STATUS=3, ID=12, ZONE=18.
    let fields = attrs::<19>(&payload[4..])?;
    let status = u32::from_be_bytes(scalar(fields[3])?);
    if status & (IPS_SRC_NAT | IPS_DST_NAT) == 0 {
        return Ok(None);
    }
    let Some((original, original_zone)) =
        tuple(fields[1].context("missing original tuple")?, family)?
    else {
        return Ok(None);
    };
    let (reply, reply_zone) = tuple(fields[2].context("missing reply tuple")?, family)?
        .context("reply tuple is not TCP")?;
    let translated = reply.reverse();
    if original == translated {
        return Ok(None);
    }
    let zone = fields[18]
        .map(|value| scalar(Some(value)).map(u16::from_be_bytes))
        .transpose()?
        .unwrap_or(0);
    Ok(Some(NatEvent {
        schema_version: SCHEMA_VERSION,
        record: "conntrack_nat".to_owned(),
        hook: HOOK.to_owned(),
        receipt_monotonic_ns: stamp,
        conntrack_netns_inum: namespace,
        conntrack_id: fields[12]
            .map(|value| scalar(Some(value)).map(u32::from_be_bytes))
            .transpose()?,
        original_zone: original_zone.unwrap_or(zone),
        reply_zone: reply_zone.unwrap_or(zone),
        original,
        reply,
        translated,
        source_nat: status & IPS_SRC_NAT != 0,
        destination_nat: status & IPS_DST_NAT != 0,
        notice,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attribute(kind: u16, data: &[u8]) -> Vec<u8> {
        let len = (data.len() + 4) as u16;
        let mut encoded = len.to_ne_bytes().to_vec();
        encoded.extend_from_slice(&kind.to_ne_bytes());
        encoded.extend_from_slice(data);
        encoded.resize(encoded.len().next_multiple_of(4), 0);
        encoded
    }

    fn write_tuple(pair: Tuple, zone: Option<u16>) -> Vec<u8> {
        let mut address = Vec::new();
        match (pair.src.address, pair.dst.address) {
            (IpAddr::V4(src), IpAddr::V4(dst)) => {
                address.extend(attribute(1, &src.octets()));
                address.extend(attribute(2, &dst.octets()));
            }
            (IpAddr::V6(src), IpAddr::V6(dst)) => {
                address.extend(attribute(3, &src.octets()));
                address.extend(attribute(4, &dst.octets()));
            }
            _ => panic!("mixed address family"),
        }
        let mut proto = attribute(1, &[6]);
        proto.extend(attribute(2, &pair.src.port.unwrap().to_be_bytes()));
        proto.extend(attribute(3, &pair.dst.port.unwrap().to_be_bytes()));
        let mut encoded = attribute(0x8001, &address);
        encoded.extend(attribute(0x8002, &proto));
        if let Some(zone) = zone {
            encoded.extend(attribute(3, &zone.to_be_bytes()));
        }
        encoded
    }

    fn sample(original: Tuple, translated: Tuple, status: u32) -> Vec<u8> {
        let family = if original.src.address.is_ipv4() {
            libc::AF_INET
        } else {
            libc::AF_INET6
        };
        let mut bytes = vec![family as u8, 0, 0, 0];
        bytes.extend(attribute(0x8001, &write_tuple(original, Some(9))));
        bytes.extend(attribute(0x8002, &write_tuple(translated.reverse(), None)));
        bytes.extend(attribute(3, &status.to_be_bytes()));
        bytes.extend(attribute(12, &0xcabf_2473_u32.to_be_bytes()));
        bytes.extend(attribute(18, &3_u16.to_be_bytes()));
        bytes
    }

    fn endpoint(address: &str, port: u16) -> Endpoint {
        Endpoint {
            address: address.parse().unwrap(),
            port: Some(port),
        }
    }

    #[test]
    fn reads_original_reply_and_double_nat_in_network_byte_order() {
        let original = Tuple {
            src: endpoint("192.0.2.2", 50525),
            dst: endpoint("203.0.113.9", 8443),
        };
        let translated = Tuple {
            src: endpoint("198.51.100.1", 40000),
            dst: endpoint("198.51.100.2", 8080),
        };
        let bytes = sample(original, translated, IPS_SRC_NAT | IPS_DST_NAT);
        let event = decode(CT_NEW, libc::NLM_F_CREATE as u16, &bytes, 10, 20)
            .unwrap()
            .unwrap();
        assert!(event.is_new());
        assert_eq!(event.original, original);
        assert_eq!(event.reply, translated.reverse());
        assert_eq!(event.translated, translated);
        assert_eq!(event.conntrack_id, Some(0xcabf_2473));
        assert_eq!((event.original_zone, event.reply_zone), (9, 3));
        assert!(event.source_nat && event.destination_nat);
        assert_eq!(
            (event.receipt_monotonic_ns, event.conntrack_netns_inum),
            (10, 20)
        );
    }

    #[test]
    fn reads_ipv6_and_rejects_corrupt_or_non_nat_messages() {
        let original = Tuple {
            src: endpoint("2001:db8::2", 50001),
            dst: endpoint("2001:db8::9", 8443),
        };
        let translated = Tuple {
            src: original.src,
            dst: endpoint("2001:db8:2::2", 8080),
        };
        let bytes = sample(original, translated, IPS_DST_NAT);
        let event = decode(CT_DELETE, 0, &bytes, 10, 20).unwrap().unwrap();
        assert_eq!(event.notice, Notice::Destroy);
        assert_eq!(event.translated, translated);
        assert!(decode(CT_NEW, 0, &bytes[..bytes.len() - 1], 10, 20).is_err());
        assert!(
            decode(CT_NEW, 0, &sample(original, translated, 0), 10, 20)
                .unwrap()
                .is_none()
        );
        assert!(
            decode(CT_NEW, 0, &sample(original, original, IPS_DST_NAT), 10, 20)
                .unwrap()
                .is_none()
        );
    }
}
