use std::{
    ffi::CString,
    io,
    os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd},
};

use anyhow::{Context, Result};
use libbpf_rs::libbpf_sys;
use serde::{Deserialize, Serialize};

pub const INGRESS: &str = "tcx/ingress";
pub const EGRESS: &str = "tcx/egress";

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    Ingress,
    Egress,
}

impl Direction {
    pub fn hook(self) -> &'static str {
        match self {
            Self::Ingress => INGRESS,
            Self::Egress => EGRESS,
        }
    }
}

#[derive(Serialize)]
pub struct Interface {
    pub name: String,
    pub ifindex: u32,
    pub netns_inum: u32,
}

impl Interface {
    pub fn resolve(name: &str) -> Result<Self> {
        let c_name = CString::new(name).context("invalid interface name")?;
        // The C string is NUL-terminated and retained until the lookup returns.
        let ifindex = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
        if ifindex == 0 {
            return Err(io::Error::last_os_error())
                .with_context(|| format!("resolve interface {name} in the current namespace"));
        }
        let netns_inum = crate::netns::current_inode()?;
        Ok(Self {
            name: name.to_owned(),
            ifindex,
            netns_inum,
        })
    }

    pub fn attach(&self, program: &impl AsFd, direction: Direction) -> Result<OwnedFd> {
        let attach_type = match direction {
            Direction::Ingress => libbpf_sys::BPF_TCX_INGRESS,
            Direction::Egress => libbpf_sys::BPF_TCX_EGRESS,
        };
        // TCX addresses the device by ifindex and returns an unpinned link FD.
        // The program is held open for the call, and null selects default options.
        let fd = unsafe {
            libbpf_sys::bpf_link_create(
                program.as_fd().as_raw_fd(),
                self.ifindex as i32,
                attach_type,
                std::ptr::null(),
            )
        };
        if fd < 0 {
            return Err(io::Error::from_raw_os_error(-fd)).with_context(|| {
                format!(
                    "attach {} to {} (requires TCX and CAP_NET_ADMIN)",
                    direction.hook(),
                    self.name
                )
            });
        }
        // The successful syscall transfers ownership of the new link FD.
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }
}
