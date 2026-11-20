use std::{
    mem::MaybeUninit,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    num::NonZeroU64,
};

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};

use crate::{
    probes::{ACCEPT, BRIDGE_FORWARD, CONNECT, IPV4_FORWARD, IPV6_FORWARD, RETRANSMIT, STATE},
    tc::Direction,
};

pub const SCHEMA_VERSION: u8 = 2;
const EVENT_SIZE: usize = 128;

#[derive(Serialize)]
#[serde(untagged)]
pub enum RingEvent {
    Socket(TcpEvent),
    Tc(TcEvent),
    Bridge(BridgeEvent),
    Route(RouteEvent),
}

#[derive(Deserialize, Serialize)]
pub struct TcEvent {
    schema_version: u8,
    record: String,
    hook: String,
    pub direction: Direction,
    pub monotonic_ns: u64,
    estimated_wall_ns: Option<u64>,
    cpu: u32,
    pub netns_inum: u32,
    pub ifindex: u32,
    pub src: Endpoint,
    pub dst: Endpoint,
    pub tcp_flags: u8,
    skb_len: u32,
}

#[derive(Deserialize, Serialize)]
pub struct BridgeEvent {
    schema_version: u8,
    record: String,
    hook: String,
    pub monotonic_ns: u64,
    estimated_wall_ns: Option<u64>,
    cpu: u32,
    pub netns_inum: u32,
    pub bridge_ifindex: u32,
    pub ingress_ifindex: Option<u32>,
    pub egress_ifindex: u32,
    pub local_origin: bool,
    src_mac: String,
    dst_mac: String,
    ether_type: u16,
    skb_len: u32,
}

#[derive(Deserialize, Serialize)]
pub struct RouteEvent {
    schema_version: u8,
    record: String,
    hook: String,
    pub monotonic_ns: u64,
    estimated_wall_ns: Option<u64>,
    cpu: u32,
    pub netns_inum: u32,
    pub ingress_ifindex: u32,
    pub egress_ifindex: u32,
    pub ip_version: u8,
    pub src: IpAddr,
    pub dst: IpAddr,
    hop_limit: u8,
    ip_next_header: u8,
    skb_len: u32,
}

impl RouteEvent {
    pub fn expected_hook(&self) -> Option<&'static str> {
        match (self.ip_version, self.src.is_ipv4(), self.dst.is_ipv4()) {
            (4, true, true) => Some(IPV4_FORWARD),
            (6, false, false) => Some(IPV6_FORWARD),
            _ => None,
        }
    }
}

fn mac_address(bytes: [u8; 6]) -> String {
    let [a, b, c, d, e, f] = bytes;
    format!("{a:02x}:{b:02x}:{c:02x}:{d:02x}:{e:02x}:{f:02x}")
}

impl RingEvent {
    pub fn decode(bytes: &[u8], clock: &ClockCalibration) -> Result<Self> {
        let bytes: &[u8; EVENT_SIZE] = bytes.try_into().context("wrong BPF record size")?;
        if bytes[67] == 7 {
            let schema_version = bytes[66];
            ensure!(
                schema_version == SCHEMA_VERSION,
                "unsupported schema version {schema_version}"
            );
            let monotonic_ns = u64::from_le_bytes(field(bytes, 0));
            let ingress = u32::from_le_bytes(field(bytes, 48));
            return Ok(Self::Bridge(BridgeEvent {
                schema_version,
                record: "bridge_forward".to_owned(),
                hook: BRIDGE_FORWARD.to_owned(),
                monotonic_ns,
                estimated_wall_ns: clock.estimate(monotonic_ns),
                cpu: u32::from_le_bytes(field(bytes, 32)),
                netns_inum: u32::from_le_bytes(field(bytes, 44)),
                bridge_ifindex: u32::from_le_bytes(field(bytes, 52)),
                ingress_ifindex: (ingress != 0).then_some(ingress),
                egress_ifindex: u32::from_le_bytes(field(bytes, 100)),
                local_origin: u32::from_le_bytes(field(bytes, 124)) != 0,
                src_mac: mac_address(field(bytes, 68)),
                dst_mac: mac_address(field(bytes, 84)),
                ether_type: u16::from_le_bytes(field(bytes, 60)),
                skb_len: u32::from_le_bytes(field(bytes, 56)),
            }));
        }
        if bytes[67] == 8 {
            let schema_version = bytes[66];
            ensure!(
                schema_version == SCHEMA_VERSION,
                "unsupported schema version {schema_version}"
            );
            let monotonic_ns = u64::from_le_bytes(field(bytes, 0));
            let family = u16::from_le_bytes(field(bytes, 60));
            let (ip_version, hook) = match i32::from(family) {
                libc::AF_INET => (4, IPV4_FORWARD),
                libc::AF_INET6 => (6, IPV6_FORWARD),
                _ => bail!("unsupported route address family {family}"),
            };
            return Ok(Self::Route(RouteEvent {
                schema_version,
                record: "route_forward".to_owned(),
                hook: hook.to_owned(),
                monotonic_ns,
                estimated_wall_ns: clock.estimate(monotonic_ns),
                cpu: u32::from_le_bytes(field(bytes, 32)),
                netns_inum: u32::from_le_bytes(field(bytes, 44)),
                ingress_ifindex: u32::from_le_bytes(field(bytes, 48)),
                egress_ifindex: u32::from_le_bytes(field(bytes, 100)),
                ip_version,
                src: Endpoint::read(family, field(bytes, 68), 0)?.address,
                dst: Endpoint::read(family, field(bytes, 84), 0)?.address,
                hop_limit: u8::try_from(u32::from_le_bytes(field(bytes, 52)))
                    .context("invalid hop limit")?,
                ip_next_header: u8::try_from(u32::from_le_bytes(field(bytes, 124)))
                    .context("invalid next header")?,
                skb_len: u32::from_le_bytes(field(bytes, 56)),
            }));
        }
        let direction = match bytes[67] {
            5 => Direction::Ingress,
            6 => Direction::Egress,
            _ => return Ok(Self::Socket(TcpEvent::decode(bytes, clock)?)),
        };
        let schema_version = bytes[66];
        ensure!(
            schema_version == SCHEMA_VERSION,
            "unsupported schema version {schema_version}"
        );
        let family = u16::from_le_bytes(field(bytes, 60));
        let monotonic_ns = u64::from_le_bytes(field(bytes, 0));
        Ok(Self::Tc(TcEvent {
            schema_version,
            record: "tc_packet".to_owned(),
            hook: direction.hook().to_owned(),
            direction,
            monotonic_ns,
            estimated_wall_ns: clock.estimate(monotonic_ns),
            cpu: u32::from_le_bytes(field(bytes, 32)),
            netns_inum: u32::from_le_bytes(field(bytes, 44)),
            ifindex: u32::from_le_bytes(field(bytes, 100)),
            src: Endpoint::read(
                family,
                field(bytes, 68),
                u16::from_le_bytes(field(bytes, 62)),
            )?,
            dst: Endpoint::read(
                family,
                field(bytes, 84),
                u16::from_le_bytes(field(bytes, 64)),
            )?,
            tcp_flags: u8::try_from(u32::from_le_bytes(field(bytes, 48)))
                .context("invalid TC TCP flags")?,
            skb_len: u32::from_le_bytes(field(bytes, 56)),
        }))
    }
}

#[derive(Debug, Serialize)]
pub struct TcpEvent {
    schema_version: u8,
    hook: &'static str,
    monotonic_ns: u64,
    estimated_wall_ns: Option<u64>,
    context_cgroup_id: u64,
    socket_cookie: Option<NonZeroU64>,
    cpu: u32,
    context_tgid: u32,
    context_tid: u32,
    netns_inum: Option<u32>,
    family: u16,
    local: Endpoint,
    remote: Endpoint,
    bound_ifindex: Option<i32>,
    #[serde(flatten)]
    observation: Observation,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub(crate) struct Endpoint {
    pub address: IpAddr,
    pub port: Option<u16>,
}

impl Endpoint {
    fn read(family: u16, address: [u8; 16], port: u16) -> Result<Self> {
        let address = match i32::from(family) {
            libc::AF_INET => IpAddr::V4(Ipv4Addr::new(
                address[0], address[1], address[2], address[3],
            )),
            libc::AF_INET6 => IpAddr::V6(Ipv6Addr::from(address)),
            _ => bail!("unsupported address family {family}"),
        };
        Ok(Self {
            address,
            port: (port != 0).then_some(port),
        })
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "record", rename_all = "snake_case")]
pub(crate) enum Observation {
    SocketState {
        oldstate: i32,
        newstate: i32,
    },
    TcpConnect {
        result: i32,
        connect_elapsed_ns: Option<NonZeroU64>,
        requested_peer: Option<Endpoint>,
    },
    TcpAccept,
    TcpRetransmit {
        socket_state: i32,
        result: i32,
    },
}

impl TcpEvent {
    pub fn decode(bytes: &[u8], clock: &ClockCalibration) -> Result<Self> {
        let bytes: &[u8; EVENT_SIZE] = bytes.try_into().context("wrong TCP record size")?;
        let version = bytes[66];
        ensure!(
            version == SCHEMA_VERSION,
            "unsupported schema version {version}"
        );

        // These offsets are the fixed little-endian V2 layout in lnfr.bpf.c.
        let monotonic_ns = u64::from_le_bytes(field(bytes, 0));
        let family = u16::from_le_bytes(field(bytes, 60));
        let result = i32::from_le_bytes(field(bytes, 56));
        let newstate = i32::from_le_bytes(field(bytes, 52));

        let (hook, observation) = match bytes[67] {
            1 => (
                STATE,
                Observation::SocketState {
                    oldstate: i32::from_le_bytes(field(bytes, 48)),
                    newstate,
                },
            ),
            2 => {
                let requested_family = u16::from_le_bytes(field(bytes, 122));
                let requested_peer = if requested_family == 0 {
                    None
                } else {
                    Some(Endpoint::read(
                        requested_family,
                        field(bytes, 104),
                        u16::from_le_bytes(field(bytes, 120)),
                    )?)
                };
                (
                    CONNECT,
                    Observation::TcpConnect {
                        result,
                        connect_elapsed_ns: NonZeroU64::new(u64::from_le_bytes(field(bytes, 24))),
                        requested_peer,
                    },
                )
            }
            3 => (ACCEPT, Observation::TcpAccept),
            4 => (
                RETRANSMIT,
                Observation::TcpRetransmit {
                    socket_state: newstate,
                    result,
                },
            ),
            kind => bail!("unsupported event kind {kind}"),
        };
        let netns = u32::from_le_bytes(field(bytes, 44));
        let ifindex = i32::from_le_bytes(field(bytes, 100));
        Ok(Self {
            schema_version: version,
            hook,
            monotonic_ns,
            estimated_wall_ns: clock.estimate(monotonic_ns),
            context_cgroup_id: u64::from_le_bytes(field(bytes, 8)),
            socket_cookie: NonZeroU64::new(u64::from_le_bytes(field(bytes, 16))),
            cpu: u32::from_le_bytes(field(bytes, 32)),
            context_tgid: u32::from_le_bytes(field(bytes, 36)),
            context_tid: u32::from_le_bytes(field(bytes, 40)),
            netns_inum: (netns != 0).then_some(netns),
            family,
            local: Endpoint::read(
                family,
                field(bytes, 68),
                u16::from_le_bytes(field(bytes, 62)),
            )?,
            remote: Endpoint::read(
                family,
                field(bytes, 84),
                u16::from_le_bytes(field(bytes, 64)),
            )?,
            bound_ifindex: (ifindex > 0).then_some(ifindex),
            observation,
        })
    }
}

fn field<const N: usize>(record: &[u8; EVENT_SIZE], start: usize) -> [u8; N] {
    record[start..start + N].try_into().unwrap()
}

#[derive(Serialize)]
pub struct ClockCalibration {
    monotonic_ns: u64,
    realtime_ns: u64,
    sampling_uncertainty_ns: u64,
}

impl ClockCalibration {
    pub fn sample() -> Result<Self> {
        let before = clock_ns(libc::CLOCK_MONOTONIC)?;
        let realtime_ns = clock_ns(libc::CLOCK_REALTIME)?;
        let after = clock_ns(libc::CLOCK_MONOTONIC)?;
        let interval = after - before;
        Ok(Self {
            monotonic_ns: before + interval / 2,
            realtime_ns,
            sampling_uncertainty_ns: interval.div_ceil(2),
        })
    }

    fn estimate(&self, monotonic_ns: u64) -> Option<u64> {
        let delta = i128::from(monotonic_ns) - i128::from(self.monotonic_ns);
        (i128::from(self.realtime_ns) + delta).try_into().ok()
    }
}

pub(crate) fn clock_ns(clock: libc::clockid_t) -> Result<u64> {
    let mut time = MaybeUninit::<libc::timespec>::uninit();
    // clock_gettime initializes the supplied timespec on success.
    if unsafe { libc::clock_gettime(clock, time.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error()).context("read capture clock");
    }
    // The system call succeeded and initialized time.
    let time = unsafe { time.assume_init() };
    let seconds = u64::try_from(time.tv_sec).context("capture clock before its epoch")?;
    let nanos = u64::try_from(time.tv_nsec).context("invalid capture clock nanoseconds")?;
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|seconds_ns| seconds_ns.checked_add(nanos))
        .context("capture clock does not fit in u64 nanoseconds")
}

#[cfg(test)]
mod tests {
    use super::*;

    const CLOCK: ClockCalibration = ClockCalibration {
        monotonic_ns: 0x0102_0304_0506_0700,
        realtime_ns: 1_000,
        sampling_uncertainty_ns: 9,
    };

    fn record(kind: u8) -> [u8; EVENT_SIZE] {
        let mut bytes = [0; EVENT_SIZE];
        bytes[..8].copy_from_slice(&[8, 7, 6, 5, 4, 3, 2, 1]);
        bytes[32..34].copy_from_slice(&[0x2c, 1]);
        bytes[36..38].copy_from_slice(&[0x34, 0x12]);
        bytes[44..48].copy_from_slice(&[0x78, 0x56, 0x34, 0x12]);
        bytes[48] = 7;
        bytes[52] = 2;
        bytes[60] = 2;
        bytes[62..64].copy_from_slice(&[0x34, 0x12]);
        bytes[64..66].copy_from_slice(&[0x90, 0x1f]);
        bytes[66] = 2;
        bytes[67] = kind;
        bytes[68..72].copy_from_slice(&[192, 0, 2, 1]);
        bytes[84..88].copy_from_slice(&[192, 0, 2, 2]);
        bytes
    }

    fn json(bytes: &[u8]) -> serde_json::Value {
        serde_json::to_value(TcpEvent::decode(bytes, &CLOCK).unwrap()).unwrap()
    }

    #[test]
    fn decodes_ipv4_state_and_little_endian_scalars() {
        let event = json(&record(1));
        assert_eq!(event["record"], "socket_state");
        assert_eq!(event["hook"], STATE);
        assert_eq!(event["monotonic_ns"], 0x0102_0304_0506_0708_u64);
        assert_eq!(event["estimated_wall_ns"], 1_008);
        assert_eq!(event["cpu"], 300);
        assert_eq!(event["context_tgid"], 0x1234);
        assert_eq!(event["netns_inum"], 0x1234_5678);
        assert_eq!(event["oldstate"], 7);
        assert_eq!(event["newstate"], 2);
        assert_eq!(
            event["local"],
            serde_json::json!({"address":"192.0.2.1","port":4660})
        );
        assert_eq!(
            event["remote"],
            serde_json::json!({"address":"192.0.2.2","port":8080})
        );
        assert!(event["socket_cookie"].is_null());
    }

    #[test]
    fn decodes_ipv6_connect_refusal_and_requested_peer() {
        let mut bytes = record(2);
        bytes[24] = 42;
        bytes[56..60].copy_from_slice(&(-libc::ECONNREFUSED).to_le_bytes());
        bytes[60] = 10;
        bytes[68..84].copy_from_slice(&"2001:db8::1".parse::<Ipv6Addr>().unwrap().octets());
        bytes[84..100].copy_from_slice(&"2001:db8::2".parse::<Ipv6Addr>().unwrap().octets());
        bytes[104..120].copy_from_slice(&"2001:db8::3".parse::<Ipv6Addr>().unwrap().octets());
        bytes[120..124].copy_from_slice(&[0x90, 0x1f, 10, 0]);
        let event = json(&bytes);
        assert_eq!(event["record"], "tcp_connect");
        assert_eq!(event["hook"], CONNECT);
        assert_eq!(event["result"], -libc::ECONNREFUSED);
        assert_eq!(event["connect_elapsed_ns"], 42);
        assert_eq!(event["local"]["address"], "2001:db8::1");
        assert_eq!(event["remote"]["address"], "2001:db8::2");
        assert_eq!(
            event["requested_peer"],
            serde_json::json!({"address":"2001:db8::3","port":8080})
        );
    }

    #[test]
    fn distinguishes_accept_and_retransmit() {
        let accept = json(&record(3));
        assert_eq!(accept["record"], "tcp_accept");
        assert_eq!(accept["hook"], ACCEPT);
        assert!(accept.get("result").is_none());
        let retransmit = json(&record(4));
        assert_eq!(retransmit["record"], "tcp_retransmit");
        assert_eq!(retransmit["hook"], RETRANSMIT);
        assert_eq!(retransmit["socket_state"], 2);
        assert_eq!(retransmit["result"], 0);
    }

    #[test]
    fn decodes_tc_direction_interface_and_tcp_flags() {
        let mut bytes = record(5);
        bytes[48..52].copy_from_slice(&0x12_u32.to_le_bytes());
        bytes[56..60].copy_from_slice(&74_u32.to_le_bytes());
        bytes[100..104].copy_from_slice(&12_u32.to_le_bytes());
        for (kind, direction) in [(5, "ingress"), (6, "egress")] {
            bytes[67] = kind;
            let event = serde_json::to_value(RingEvent::decode(&bytes, &CLOCK).unwrap()).unwrap();
            assert_eq!(event["record"], "tc_packet");
            assert_eq!(event["hook"], format!("tcx/{direction}"));
            assert_eq!(event["direction"], direction);
            assert_eq!(event["ifindex"], 12);
            assert_eq!(event["tcp_flags"], 0x12);
            assert_eq!(event["skb_len"], 74);
            assert_eq!(event["src"]["address"], "192.0.2.1");
            assert_eq!(event["dst"]["port"], 8080);
            assert!(event.get("socket_cookie").is_none());
        }
    }

    #[test]
    fn decodes_bridge_forwarding_and_distinguishes_local_origin() {
        let mut bytes = record(7);
        bytes[48..52].copy_from_slice(&11_u32.to_le_bytes());
        bytes[52..56].copy_from_slice(&10_u32.to_le_bytes());
        bytes[56..60].copy_from_slice(&60_u32.to_le_bytes());
        bytes[60..62].copy_from_slice(&0x0800_u16.to_le_bytes());
        bytes[68..74].copy_from_slice(&[2, 0, 0, 0, 0, 0x11]);
        bytes[84..90].copy_from_slice(&[2, 0, 0, 0, 0, 0x22]);
        bytes[100..104].copy_from_slice(&12_u32.to_le_bytes());
        let event = serde_json::to_value(RingEvent::decode(&bytes, &CLOCK).unwrap()).unwrap();
        assert_eq!(event["record"], "bridge_forward");
        assert_eq!(event["hook"], BRIDGE_FORWARD);
        assert_eq!(event["ingress_ifindex"], 11);
        assert_eq!(event["bridge_ifindex"], 10);
        assert_eq!(event["egress_ifindex"], 12);
        assert_eq!(event["src_mac"], "02:00:00:00:00:11");
        assert_eq!(event["dst_mac"], "02:00:00:00:00:22");
        assert_eq!(event["ether_type"], 0x0800);
        assert_eq!(event["local_origin"], false);

        bytes[48..52].fill(0);
        bytes[124] = 1;
        let event = serde_json::to_value(RingEvent::decode(&bytes, &CLOCK).unwrap()).unwrap();
        assert!(event["ingress_ifindex"].is_null());
        assert_eq!(event["local_origin"], true);
    }

    #[test]
    fn decodes_ipv4_and_ipv6_forwarding_with_selected_ifindex() {
        let mut bytes = record(8);
        bytes[48..52].copy_from_slice(&11_u32.to_le_bytes());
        bytes[52..56].copy_from_slice(&48_u32.to_le_bytes());
        bytes[56..60].copy_from_slice(&60_u32.to_le_bytes());
        bytes[100..104].copy_from_slice(&12_u32.to_le_bytes());
        bytes[124] = 6;
        let event = serde_json::to_value(RingEvent::decode(&bytes, &CLOCK).unwrap()).unwrap();
        assert_eq!(event["record"], "route_forward");
        assert_eq!(event["hook"], IPV4_FORWARD);
        assert_eq!(event["ingress_ifindex"], 11);
        assert_eq!(event["egress_ifindex"], 12);
        assert_eq!(event["hop_limit"], 48);
        assert_eq!(event["ip_next_header"], 6);
        assert_eq!(event["dst"], "192.0.2.2");

        bytes[60] = 10;
        bytes[68..84].copy_from_slice(&"2001:db8:10::2".parse::<Ipv6Addr>().unwrap().octets());
        bytes[84..100].copy_from_slice(&"2001:db8:20::2".parse::<Ipv6Addr>().unwrap().octets());
        bytes[124] = 44;
        let event = serde_json::to_value(RingEvent::decode(&bytes, &CLOCK).unwrap()).unwrap();
        assert_eq!(event["ip_version"], 6);
        assert_eq!(event["hook"], IPV6_FORWARD);
        assert_eq!(event["dst"], "2001:db8:20::2");
        assert_eq!(event["ip_next_header"], 44);
    }

    #[test]
    fn rejects_wrong_length_version_kind_and_family() {
        assert!(TcpEvent::decode(&record(1)[..127], &CLOCK).is_err());
        let mut version = record(1);
        version[66] = 1;
        assert!(TcpEvent::decode(&version, &CLOCK).is_err());
        assert!(TcpEvent::decode(&record(5), &CLOCK).is_err());
        let mut family = record(1);
        family[60] = 3;
        assert!(TcpEvent::decode(&family, &CLOCK).is_err());
    }
}
