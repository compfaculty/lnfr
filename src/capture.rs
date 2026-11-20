use std::{
    cell::RefCell,
    collections::BTreeMap,
    io::{self, Write},
    mem::MaybeUninit,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use anyhow::{Context, Result, ensure};
use libbpf_rs::{
    Link, MapCore, MapFlags, RingBuffer, RingBufferBuilder,
    skel::{OpenSkel, SkelBuilder},
};
use serde::Serialize;
use serde_json::json;
use signal_hook::{
    consts::signal::{SIGINT, SIGTERM},
    flag,
};

use crate::{
    conntrack,
    event::{ClockCalibration, RingEvent, SCHEMA_VERSION},
    probes::{
        ACCEPT, BRIDGE_FORWARD, CONNECT, CONNECT_ENTRY, Features, IPV4_FORWARD, IPV6_FORWARD,
        RETRANSMIT, STATE, bridge_module_btf,
    },
    tc::{self, Direction},
};

mod bpf {
    include!(concat!(env!("OUT_DIR"), "/lnfr.skel.rs"));
}

const POLL_INTERVAL: Duration = Duration::from_millis(100);

#[derive(Default, Serialize)]
struct Counters {
    submitted: u64,
    ring_lost: u64,
    rate_limited: u64,
    connect_tracking_lost: u64,
}

impl Counters {
    fn read(map: &impl MapCore) -> Result<Self> {
        let values = map
            .lookup_percpu(&0_u32.to_ne_bytes(), MapFlags::ANY)
            .context("read per-CPU capture counters")?
            .context("capture counters key missing")?;
        let mut total = Self::default();
        for value in values {
            let value: [u8; 48] = value.try_into().ok().context("unexpected counter layout")?;
            // The first two u64 fields are the rate limiter's current window.
            total.submitted += u64::from_le_bytes(value[16..24].try_into().unwrap());
            total.ring_lost += u64::from_le_bytes(value[24..32].try_into().unwrap());
            total.rate_limited += u64::from_le_bytes(value[32..40].try_into().unwrap());
            total.connect_tracking_lost += u64::from_le_bytes(value[40..48].try_into().unwrap());
        }
        Ok(total)
    }
}

pub struct Options<'a> {
    pub duration: Option<Duration>,
    pub tgid: Option<u32>,
    pub netns_inum: Option<u32>,
    pub state_only: bool,
    pub subscribe_conntrack: bool,
    pub tc_interface: Option<&'a str>,
    pub bridge_interface: Option<&'a str>,
    pub routing: bool,
}

pub fn run(options: Options<'_>) -> Result<()> {
    let Options {
        duration,
        tgid,
        netns_inum,
        state_only,
        subscribe_conntrack,
        tc_interface,
        bridge_interface,
        routing,
    } = options;
    let route_netns = routing.then(crate::netns::current_inode).transpose()?;
    let tc = tc_interface.map(tc::Interface::resolve).transpose()?;
    let bridge = bridge_interface.map(tc::Interface::resolve).transpose()?;
    ensure!(
        bridge.is_none() || bridge_module_btf(),
        "{BRIDGE_FORWARD} requires the loaded Linux bridge module and its BTF"
    );
    let mut conntrack = subscribe_conntrack
        .then(conntrack::Listener::open)
        .transpose()
        .context("enable --conntrack")?;
    let features = Features::detect();
    ensure!(
        features.state != Some(false),
        "{STATE} is not visible in tracefs"
    );
    let route4 = routing && features.route4;
    let route6 = routing && features.route6;
    ensure!(
        !routing || route4 || route6,
        "no compatible IPv4 or IPv6 forwarding hook in kernel BTF"
    );
    let stop = Arc::new(AtomicBool::new(false));
    flag::register(SIGINT, Arc::clone(&stop)).context("register Ctrl+C handler")?;
    flag::register(SIGTERM, Arc::clone(&stop)).context("register termination handler")?;
    if duration.is_none() {
        let stop = Arc::clone(&stop);
        std::thread::Builder::new()
            .name("capture-control".to_owned())
            .spawn(move || {
                let _ = io::copy(&mut io::stdin().lock(), &mut io::sink());
                stop.store(true, Ordering::Relaxed);
            })
            .context("monitor capture control input")?;
    }

    let mut object = MaybeUninit::uninit();
    let mut open = bpf::LnfrSkelBuilder::default()
        .open(&mut object)
        .context("open embedded BPF object")?;
    let config = open
        .maps
        .rodata_data
        .as_mut()
        .context("missing BPF configuration")?;
    config.target_tgid = tgid.unwrap_or(0);
    config.target_netns = netns_inum.unwrap_or(0);
    config.route_netns = route_netns.unwrap_or(0);
    config.tc_netns = tc.as_ref().map_or(0, |interface| interface.netns_inum);
    config.bridge_netns = bridge.as_ref().map_or(0, |interface| interface.netns_inum);
    config.bridge_ifindex = bridge.as_ref().map_or(0, |interface| interface.ifindex);
    let events_per_cpu_per_second = config.events_per_cpu_per_second;
    let retransmit = !state_only && features.retransmit != Some(false);
    let connect = !state_only && features.connect;
    let accept = !state_only && features.accept;
    open.progs.on_retransmit.set_autoload(retransmit);
    open.progs.on_connect_exit.set_autoload(connect);
    open.progs.on_connect_enter.set_autoload(connect);
    open.progs.on_accept.set_autoload(accept);
    open.progs.on_tc_ingress.set_autoload(tc.is_some());
    open.progs.on_tc_egress.set_autoload(tc.is_some());
    open.progs.on_bridge_forward.set_autoload(bridge.is_some());
    open.progs.on_ipv4_forward.set_autoload(route4);
    open.progs.on_ipv6_forward.set_autoload(route6);

    let skel = open.load().with_context(|| {
        let fallback = if state_only {
            ""
        } else {
            "; use --state-only to isolate optional hooks"
        };
        let tc_hint = if tc.is_some() {
            "; omit --tc-interface to isolate TCX"
        } else {
            ""
        };
        let bridge_hint = if bridge.is_some() {
            "; omit --bridge-interface to isolate the bridge probe"
        } else {
            ""
        };
        let route_hint = if routing { "; omit --routing to isolate forwarding probes" } else { "" };
        format!(
            "load BPF probes (requires BPF privileges and compatible kernel BTF{fallback}{tc_hint}{bridge_hint}{route_hint})"
        )
    })?;
    let clock = ClockCalibration::sample()?;
    let state_link = skel.progs.on_socket_state.attach().with_context(|| {
        format!("attach {STATE} (check tracefs visibility and tracing privileges)")
    })?;
    let mut links = vec![state_link];
    let mut active = vec![STATE];
    let mut disabled = BTreeMap::new();
    let mut optional = |hook, enabled, attach: &dyn Fn() -> libbpf_rs::Result<Link>| {
        let reason = if enabled {
            match attach() {
                Ok(link) => {
                    links.push(link);
                    active.push(hook);
                    return true;
                }
                Err(error) => format!("attach failed: {error}"),
            }
        } else if state_only {
            "state-only capture requested".to_owned()
        } else {
            "required kernel metadata or companion hook unavailable".to_owned()
        };
        disabled.insert(hook, reason);
        false
    };
    optional(RETRANSMIT, retransmit, &|| {
        skel.progs.on_retransmit.attach()
    });
    let connect_attached = optional(CONNECT, connect, &|| skel.progs.on_connect_exit.attach());
    optional(CONNECT_ENTRY, connect_attached, &|| {
        skel.progs.on_connect_enter.attach()
    });
    optional(ACCEPT, accept, &|| skel.progs.on_accept.attach());

    if routing {
        let ipv4 = optional(IPV4_FORWARD, route4, &|| {
            skel.progs.on_ipv4_forward.attach()
        });
        let ipv6 = optional(IPV6_FORWARD, route6, &|| {
            skel.progs.on_ipv6_forward.attach()
        });
        ensure!(ipv4 || ipv6, "routing attach failed: {:?}", disabled);
    }
    if conntrack.is_some() {
        active.push(conntrack::HOOK);
    }
    if bridge.is_some() {
        let link = skel.progs.on_bridge_forward.attach().with_context(|| {
            format!("attach {BRIDGE_FORWARD} (check bridge module BTF and tracing privileges)")
        })?;
        links.push(link);
        active.push(BRIDGE_FORWARD);
    }
    let tc_links = if let Some(interface) = &tc {
        let ingress = interface.attach(&skel.progs.on_tc_ingress, Direction::Ingress)?;
        let egress = interface.attach(&skel.progs.on_tc_egress, Direction::Egress)?;
        active.extend([tc::INGRESS, tc::EGRESS]);
        Some((ingress, egress))
    } else {
        None
    };
    let start = Instant::now();
    let mut output = io::stdout().lock();
    write_record(
        &mut output,
        &json!({
            "record": "capture_start",
            "schema_version": SCHEMA_VERSION,
            "active_probes": active,
            "disabled_probes": disabled,
            "blind_spots": [
                "no packet-drop or complete packet-path coverage",
                "socket cookies may be absent; tuples can be reused",
                "process identifiers describe the hook execution context"
            ],
            "context_tgid_filter": tgid,
            "netns_inum_filter": netns_inum,
            "tc_interface": tc,
            "bridge_interface": bridge,
            "routing_netns_inum": route_netns,
            "conntrack_netns_inum": conntrack.as_ref().map(|listener| listener.netns_inum),
            "events_per_cpu_per_second": events_per_cpu_per_second,
            "duration_seconds": duration.map(|value| value.as_secs()),
            "ring_bytes": skel.maps.events.max_entries(),
            "clock_calibration": clock,
        }),
    )?;
    output.flush().context("flush capture header")?;

    let output = RefCell::new(output);
    let mut received = 0_u64;
    let mut callback_error = None;
    let mut builder = RingBufferBuilder::new();
    builder
        .add(&skel.maps.events, |bytes| {
            match RingEvent::decode(bytes, &clock)
                .and_then(|event| write_record(&mut *output.borrow_mut(), &event))
            {
                Ok(()) => {
                    received += 1;
                    0
                }
                Err(error) => {
                    callback_error = Some(error);
                    -libc::ECANCELED
                }
            }
        })
        .context("register TCP ring buffer")?;
    let ring = builder.build().context("open TCP ring buffer")?;
    let mut drain_conntrack = || {
        if let Some(listener) = &mut conntrack {
            listener.drain(|event| write_record(&mut *output.borrow_mut(), &event))?;
        }
        Ok(())
    };
    let polled = poll(
        &ring,
        &stop,
        duration.map(|value| start + value),
        &mut drain_conntrack,
    );

    // Remove the producers before draining what was already queued.
    drop(tc_links);
    drop(links);
    let drained = polled.and_then(|reason| {
        ring.consume().context("drain TCP ring buffer")?;
        drain_conntrack()?;
        Ok(reason)
    });
    drop(ring);
    if let Some(error) = callback_error {
        return Err(error).context("process TCP ring-buffer record");
    }
    let reason = drained?;

    let mut output = output.into_inner();
    let counters = Counters::read(&skel.maps.stats)?;
    write_record(
        &mut output,
        &json!({
            "record": "capture_end",
            "schema_version": SCHEMA_VERSION,
            "reason": reason,
            "elapsed_ms": start.elapsed().as_millis(),
            "received": received,
            "stats": counters,
            "conntrack_stats": conntrack.as_ref().map(|listener| &listener.stats),
        }),
    )?;
    output.flush().context("flush capture output")
}

fn poll(
    ring: &RingBuffer<'_>,
    stop: &AtomicBool,
    deadline: Option<Instant>,
    mut drain_conntrack: impl FnMut() -> Result<()>,
) -> Result<&'static str> {
    loop {
        if stop.load(Ordering::Relaxed) {
            return Ok("signal");
        }
        let remaining = deadline.map_or(POLL_INTERVAL, |end| {
            end.saturating_duration_since(Instant::now())
        });
        if remaining.is_zero() {
            return Ok("duration");
        }
        let timeout = remaining.min(POLL_INTERVAL).max(Duration::from_millis(1));
        let result = ring.poll_raw(timeout);
        if result < 0 && result != -libc::EINTR {
            return Err(io::Error::from_raw_os_error(-result)).context("poll TCP ring buffer");
        }
        drain_conntrack()?;
    }
}

fn write_record(output: &mut impl Write, record: &impl Serialize) -> Result<()> {
    serde_json::to_writer(&mut *output, record).context("write capture JSON")?;
    output.write_all(b"\n").context("finish capture JSON line")
}
