use std::path::Path;

use libbpf_rs::{
    Btf,
    btf::{BtfKind, BtfType, ReferencesType, types},
};

pub const STATE: &str = "sock:inet_sock_set_state";
pub const RETRANSMIT: &str = "tcp:tcp_retransmit_skb";
pub const CONNECT: &str = "fexit/inet_stream_connect";
pub const CONNECT_ENTRY: &str = "fentry/inet_stream_connect";
pub const ACCEPT: &str = "fexit/inet_csk_accept";
const BTF_PATH: &str = "/sys/kernel/btf/vmlinux";

pub const IPV4_FORWARD: &str = "fentry/ip_forward";
pub const IPV6_FORWARD: &str = "fentry/ip6_forward";
pub const BRIDGE_FORWARD: &str = "fentry/__br_forward";

pub fn bridge_module_btf() -> bool {
    Path::new("/sys/kernel/btf/bridge").is_file()
}

pub struct Features {
    pub state: Option<bool>,
    pub retransmit: Option<bool>,
    pub connect: bool,
    pub accept: bool,
    pub route4: bool,
    pub route6: bool,
    btf_readable: bool,
}

impl Features {
    pub fn detect() -> Self {
        let btf = Btf::from_path(BTF_PATH).ok();
        Self {
            state: tracepoint(STATE),
            retransmit: tracepoint(RETRANSMIT),
            connect: btf.as_ref().is_some_and(|btf| {
                supports_function(
                    btf,
                    "inet_stream_connect",
                    &[BtfKind::Ptr, BtfKind::Ptr, BtfKind::Int, BtfKind::Int],
                    BtfKind::Int,
                )
            }),
            accept: btf.as_ref().is_some_and(|btf| {
                supports_function(
                    btf,
                    "inet_csk_accept",
                    &[BtfKind::Ptr, BtfKind::Ptr],
                    BtfKind::Ptr,
                )
            }),
            route4: btf.as_ref().is_some_and(|btf| {
                supports_function(btf, "ip_forward", &[BtfKind::Ptr], BtfKind::Int)
            }),
            route6: btf.as_ref().is_some_and(|btf| {
                supports_function(btf, "ip6_forward", &[BtfKind::Ptr], BtfKind::Int)
            }),
            btf_readable: btf.is_some(),
        }
    }

    pub fn print(&self) {
        println!(
            "Kernel BTF ({BTF_PATH}): {}",
            available(Some(self.btf_readable))
        );
        for (hook, present) in [
            (STATE, self.state),
            (RETRANSMIT, self.retransmit),
            (CONNECT_ENTRY, Some(self.connect)),
            (CONNECT, Some(self.connect)),
            (ACCEPT, Some(self.accept)),
            (IPV4_FORWARD, Some(self.route4)),
            (IPV6_FORWARD, Some(self.route6)),
        ] {
            println!("{hook}: {}", available(present));
        }
        if let Ok(setting) = std::fs::read_to_string("/proc/sys/kernel/unprivileged_bpf_disabled") {
            println!("kernel.unprivileged_bpf_disabled: {}", setting.trim());
        }
        if let Ok(setting) = std::fs::read_to_string("/proc/sys/net/netfilter/nf_conntrack_events")
        {
            println!("net.netfilter.nf_conntrack_events: {}", setting.trim());
        }
        println!(
            "lnfr capture --conntrack verifies ctnetlink subscription in the current network namespace."
        );
        println!(
            "lnfr capture --tc-interface IFACE verifies TCX attach in the current network namespace."
        );
        println!(
            "Bridge module BTF (/sys/kernel/btf/bridge): {}",
            available(Some(bridge_module_btf()))
        );
        println!(
            "lnfr capture --bridge-interface IFACE verifies {}.",
            BRIDGE_FORWARD
        );
        println!("lnfr capture verifies load and attach permissions.");
    }
}

fn available(result: Option<bool>) -> &'static str {
    match result {
        Some(true) => "present",
        Some(false) => "unsupported or not visible",
        None => "inaccessible",
    }
}

fn tracepoint(hook: &str) -> Option<bool> {
    let (group, event) = hook.split_once(':').expect("tracepoint name");
    let mut visible = Some(false);
    for root in ["/sys/kernel/tracing", "/sys/kernel/debug/tracing"] {
        let location = Path::new(root).join(format!("events/{group}/{event}/id"));
        match location.try_exists() {
            Ok(true) => return Some(true),
            Ok(false) => {}
            Err(_) => visible = None,
        }
    }
    visible
}

fn supports_function(btf: &Btf<'_>, name: &str, args: &[BtfKind], result: BtfKind) -> bool {
    let Some(function) = btf.type_by_name::<types::Func<'_>>(name) else {
        return false;
    };
    let Some(proto) = btf.type_by_id::<types::FuncProto<'_>>(function.referenced_type_id()) else {
        return false;
    };
    proto.len() == args.len()
        && proto.referenced_type().skip_mods_and_typedefs().kind() == result
        && proto.iter().zip(args).all(|(param, expected)| {
            btf.type_by_id::<BtfType<'_>>(param.ty)
                .is_some_and(|btf_type| btf_type.skip_mods_and_typedefs().kind() == *expected)
        })
}
