use curl::easy::{Easy2, Handler, WriteError};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::HashMap,
    error::Error,
    fmt,
    io::Cursor,
    net::{IpAddr, SocketAddr},
};

// https://docs.rs/curl/0.4.39/curl/easy/struct.Easy2.html#examples
struct Collector(Vec<u8>);

impl Handler for Collector {
    fn write(&mut self, data: &[u8]) -> Result<usize, WriteError> {
        self.0.extend_from_slice(data);
        Ok(data.len())
    }
}

#[derive(Debug)]
pub struct StatusError {
    resp_code: u32,
}

impl fmt::Display for StatusError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "unexpected status code {}", self.resp_code)
    }
}

impl Error for StatusError {}

#[derive(Serialize, Deserialize)]
pub struct Status {
    #[serde(rename = "Version")]
    version: String,

    #[serde(rename = "BackendState")]
    backend_state: String,

    #[serde(rename = "AuthURL")]
    auth_url: String,

    #[serde(rename = "TailscaleIPs")]
    tailscale_ips: Vec<String>,

    #[serde(rename = "Self")]
    pub myself: Peer,

    #[serde(rename = "MagicDNSSuffix")]
    magic_dns_suffix: String,

    #[serde(rename = "CertDomains")]
    cert_domains: Vec<String>,

    #[serde(rename = "Peer")]
    pub peer: HashMap<String, Peer>,

    #[serde(rename = "User")]
    pub user: HashMap<String, User>,
}

impl Status {
    pub fn get() -> super::Result<Self> {
        let mut easy = Easy2::new(Collector(Vec::new()));
        easy.url("http://foo/localapi/v0/status")?;
        easy.unix_socket("/var/run/tailscale/tailscaled.sock")?;
        easy.perform()?;

        let resp_code = easy.response_code()?;
        if resp_code != 200 {
            return Err(StatusError { resp_code }.into());
        }

        let buf = easy.get_ref();

        Ok(serde_json::from_reader(Cursor::new(&buf.0))?)
    }

    pub fn get_peer_user(&self, id: u64) -> Option<&User> {
        for (_, user) in &self.user {
            if user.id == id {
                return Some(user);
            }
        }

        None
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct Peer {
    #[serde(rename = "ID")]
    id: Value,

    #[serde(rename = "PublicKey")]
    pub public_key: String,

    #[serde(rename = "HostName")]
    host_name: Value,

    #[serde(rename = "DNSName")]
    dns_name: Value,

    #[serde(rename = "OS")]
    os: Value,

    #[serde(rename = "UserID")]
    pub user_id: u64,

    #[serde(rename = "TailAddr")]
    tail_addr: Option<IpAddr>,

    #[serde(rename = "TailscaleIPs")]
    pub tailscale_ips: Vec<IpAddr>,

    #[serde(rename = "Addrs")]
    addrs: Value,

    #[serde(rename = "CurAddr")]
    cur_addr: Value,

    #[serde(rename = "Relay")]
    relay: String,

    #[serde(rename = "RxBytes")]
    rx_bytes: Value,

    #[serde(rename = "TxBytes")]
    tx_bytes: Value,

    #[serde(rename = "Created")]
    created: String,

    #[serde(rename = "LastWrite")]
    last_write: String,

    #[serde(rename = "LastSeen")]
    last_seen: String,

    #[serde(rename = "LastHandshake")]
    last_handshake: String,

    #[serde(rename = "KeepAlive")]
    keep_alive: bool,

    #[serde(rename = "ExitNode")]
    exit_node: Value,

    #[serde(rename = "Active")]
    active: Value,

    #[serde(rename = "PeerAPIURL")]
    peer_apiurl: Value,

    #[serde(rename = "InNetworkMap")]
    in_network_map: Value,

    #[serde(rename = "InMagicSock")]
    in_magic_sock: Value,

    #[serde(rename = "InEngine")]
    in_engine: Value,

    #[serde(rename = "Capabilities")]
    capabilities: Option<Vec<String>>,
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WhoisResponse {
    #[serde(rename = "Node")]
    pub node: WhoisPeer,
    #[serde(rename = "UserProfile")]
    pub user_profile: User,
}

impl WhoisResponse {
    pub fn get(addr: SocketAddr) -> super::Result<Self> {
        let mut u = url::Url::parse("http://foo/localapi/v0/whois")?;
        u.query_pairs_mut().append_pair("addr", &addr.to_string());

        let mut easy = Easy2::new(Collector(Vec::new()));
        easy.url(u.as_str())?;
        easy.unix_socket("/var/run/tailscale/tailscaled.sock")?;
        easy.perform()?;

        let resp_code = easy.response_code()?;
        if resp_code != 200 {
            return Err(StatusError { resp_code }.into());
        }

        let buf = easy.get_ref();

        Ok(serde_json::from_reader(Cursor::new(&buf.0))?)
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct User {
    #[serde(rename = "ID")]
    pub id: u64,

    #[serde(rename = "LoginName")]
    pub login_name: String,

    #[serde(rename = "DisplayName")]
    pub display_name: String,

    #[serde(rename = "ProfilePicURL")]
    pub profile_pic_url: String,

    #[serde(rename = "Roles")]
    pub roles: Vec<Option<serde_json::Value>>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WhoisPeer {
    #[serde(rename = "ID")]
    pub id: i64,
    #[serde(rename = "StableID")]
    pub stable_id: String,
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "User")]
    pub user: i64,
    #[serde(rename = "Key")]
    pub key: String,
    #[serde(rename = "KeyExpiry")]
    pub key_expiry: String,
    #[serde(rename = "Machine")]
    pub machine: String,
    #[serde(rename = "DiscoKey")]
    pub disco_key: String,
    #[serde(rename = "Addresses")]
    pub addresses: Vec<String>,
    #[serde(rename = "AllowedIPs")]
    pub allowed_ips: Vec<String>,
    #[serde(rename = "Endpoints")]
    pub endpoints: Vec<String>,
    #[serde(rename = "Hostinfo")]
    pub hostinfo: Hostinfo,
    #[serde(rename = "Created")]
    pub created: String,
    #[serde(rename = "PrimaryRoutes")]
    pub primary_routes: Vec<String>,
    #[serde(rename = "MachineAuthorized")]
    pub machine_authorized: bool,
    #[serde(rename = "Capabilities")]
    pub capabilities: Vec<String>,
    #[serde(rename = "ComputedName")]
    pub computed_name: String,
    #[serde(rename = "ComputedNameWithHost")]
    pub computed_name_with_host: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Hostinfo {
    #[serde(rename = "OS")]
    pub os: String,
    #[serde(rename = "Hostname")]
    pub hostname: String,
    #[serde(rename = "RoutableIPs")]
    pub routable_ips: Vec<String>,
    #[serde(rename = "Services")]
    pub services: Vec<Service>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Service {
    #[serde(rename = "Proto")]
    pub proto: String,
    #[serde(rename = "Port")]
    pub port: i64,
    #[serde(rename = "Description")]
    pub description: Option<String>,
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use super::*;

    #[test]
    fn status_get() {
        Status::get().unwrap();
    }

    #[test]
    fn whois_get() {
        let st = Status::get().unwrap();
        let sa: SocketAddr = (st.myself.tail_addr, 0).into();
        WhoisResponse::get(sa).unwrap();
    }
}
