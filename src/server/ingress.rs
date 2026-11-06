//! Per-request ingress provenance and the plaintext-remote gate.
//!
//! Forwarded headers are read here and nowhere else, and only from the immediate peer of a
//! configured proxy (`proxy_mode`, whose trusted peers are the loopback addresses every
//! supported proxy and tunnel terminates onto). Everything downstream reads the resulting
//! [`Ingress`] instead of re-deriving trust from raw headers.
//!
//! A CityHall workspace has a second way to name its trusted proxy: a shared secret. In
//! CityHall mode with `AOE_CITYHALL_PROXY_TOKEN` set, every request from a non-loopback peer
//! must carry it in `X-CityHall-Proxy-Token`, so the workspace answers only its CityHall
//! rather than anything that can reach the port. A request that carries it from a private
//! network address is treated like one from a loopback proxy: forwarded client addresses are
//! trusted and plain HTTP over that hop is accepted, because CityHall, not the browser, is the
//! party that terminates end-user TLS. The same secret from a public address buys nothing:
//! plain HTTP from there is still refused, so the secret never crosses an open network in
//! the clear.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use axum::extract::{ConnectInfo, Request, State};
use axum::http::HeaderMap;
use axum::middleware::Next;
use axum::response::Response;

use super::auth::constant_time_eq;
use super::AppState;

/// Header a CityHall proxy uses to present the workspace's shared secret.
pub(crate) const PROXY_TOKEN_HEADER: &str = "x-cityhall-proxy-token";

/// Rate-limit and login key for a proxied request that names no valid client address.
/// Such callers share one bucket; none is ever mistaken for the loopback peer.
const UNKNOWN_CLIENT: IpAddr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Ingress {
    /// Identity for login attempts and auth rate limiting.
    pub client_ip: IpAddr,
    /// The connection is not known to be encrypted and is not a direct loopback one.
    pub plaintext_remote: bool,
    /// A trusted proxy asserted that the client connected over HTTPS.
    pub externally_secure: bool,
}

impl AppState {
    pub(crate) fn ingress(&self, peer: SocketAddr, headers: &HeaderMap) -> Ingress {
        Ingress::resolve_with_proxy_auth(
            peer,
            headers,
            self.behind_tunnel,
            self.trust_cf_header,
            self.carries_proxy_token(headers),
        )
    }

    /// Whether the request presents this workspace's CityHall proxy secret. `false` when no
    /// secret is configured.
    pub(crate) fn carries_proxy_token(&self, headers: &HeaderMap) -> bool {
        let Some(expected) = self.cityhall_proxy_token.as_deref() else {
            return false;
        };
        let mut values = headers.get_all(PROXY_TOKEN_HEADER).iter();
        match (values.next(), values.next()) {
            (Some(value), None) => value
                .to_str()
                .is_ok_and(|presented| constant_time_eq(presented.trim(), expected)),
            _ => false, // missing, or repeated (ambiguous)
        }
    }
}

impl Ingress {
    pub(crate) fn resolve(
        peer: SocketAddr,
        headers: &HeaderMap,
        proxy_mode: bool,
        trust_cf_header: bool,
    ) -> Self {
        Self::resolve_with_proxy_auth(peer, headers, proxy_mode, trust_cf_header, false)
    }

    /// [`Self::resolve`] for a request that may have presented the CityHall proxy secret
    /// (`authenticated_proxy`). The secret only counts from a private network address.
    pub(crate) fn resolve_with_proxy_auth(
        peer: SocketAddr,
        headers: &HeaderMap,
        proxy_mode: bool,
        trust_cf_header: bool,
        authenticated_proxy: bool,
    ) -> Self {
        let peer_ip = peer.ip().to_canonical();
        let authenticated_private_proxy = authenticated_proxy && is_private_network(peer_ip);
        let via_trusted_proxy =
            (proxy_mode && peer_ip.is_loopback()) || authenticated_private_proxy;
        let forwarded_proto = via_trusted_proxy
            .then(|| last_list_element(headers, "x-forwarded-proto"))
            .flatten();
        let externally_secure = forwarded_proto
            .is_some_and(|p| p.eq_ignore_ascii_case("https") || p.eq_ignore_ascii_case("wss"));
        let forwarded_plaintext = forwarded_proto.is_some() && !externally_secure;
        Self {
            client_ip: if via_trusted_proxy {
                forwarded_client_ip(headers, trust_cf_header)
            } else {
                peer_ip
            },
            plaintext_remote: !authenticated_private_proxy
                && !externally_secure
                && (!peer_ip.is_loopback() || forwarded_plaintext),
            externally_secure,
        }
    }
}

/// The last comma-separated element of the last line of `name`: the entry the nearest proxy
/// appended, which a client cannot forge.
fn last_list_element<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let line = headers.get_all(name).iter().next_back()?.to_str().ok()?;
    line.rsplit(',').next().map(str::trim)
}

/// Loopback, link-local, RFC 1918 / unique-local, and the 100.64.0.0/10 shared range (CGNAT,
/// Tailscale). The addresses a workspace and its CityHall can share without crossing the open
/// internet.
pub(crate) fn is_private_network(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || (v4.octets()[0] == 100 && (v4.octets()[1] & 0xC0) == 0x40)
        }
        IpAddr::V6(v6) => v6.is_loopback() || v6.is_unique_local() || v6.is_unicast_link_local(),
    }
}

/// `cf-connecting-ip` when `trust_cf_header` and the tunnel sent it, else the last
/// `x-forwarded-for` element. A generic reverse proxy may pass a client-chosen
/// `cf-connecting-ip` through untouched, so it is ignored there. A missing, repeated or
/// malformed value is [`UNKNOWN_CLIENT`].
fn forwarded_client_ip(headers: &HeaderMap, trust_cf_header: bool) -> IpAddr {
    let mut cf = headers.get_all("cf-connecting-ip").iter();
    let parsed = match (trust_cf_header, cf.next(), cf.next()) {
        (true, Some(_), Some(_)) => None,
        (true, Some(value), None) => value.to_str().ok().and_then(|v| v.trim().parse().ok()),
        _ => last_list_element(headers, "x-forwarded-for").and_then(|v| v.parse::<IpAddr>().ok()),
    };
    parsed.unwrap_or(UNKNOWN_CLIENT)
}

/// Rejects plaintext non-loopback requests with 426 before any other gate runs, unless
/// the bind explicitly opted out.
pub(super) async fn plaintext_gate(
    State(state): State<Arc<AppState>>,
    request: Request,
    next: Next,
) -> Response {
    // The owner-only Unix listener is never remote, and an unstamped request has no peer
    // to judge: every real listener stamps one.
    let peer = match request
        .extensions()
        .get::<ConnectInfo<super::peer::ConnectionPeer>>()
    {
        Some(ConnectInfo(super::peer::ConnectionPeer::Tcp(addr))) => Some(*addr),
        Some(_) => None,
        None => request
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map(|ConnectInfo(addr)| *addr),
    };
    if let Some(peer) = peer {
        // CityHall mode with a proxy secret: the workspace answers only its CityHall (and
        // processes on its own loopback), not everything that can reach the port.
        if state.cityhall_proxy_token.is_some()
            && !peer.ip().to_canonical().is_loopback()
            && !state.carries_proxy_token(request.headers())
        {
            tracing::debug!(target: "http.access", peer = %peer.ip(), "rejected request without the CityHall proxy token");
            return super::api::api_error_with_code_header(
                crate::daemon::ApiErrorCode::ProxyAuthRequired,
                "this workspace only accepts requests from its CityHall",
            );
        }
        let ingress = state.ingress(peer, request.headers());
        if ingress.plaintext_remote && !state.allow_plaintext_remote {
            tracing::debug!(target: "http.access", peer = %peer.ip(), "rejected plaintext remote request");
            return super::api::api_error_with_code_header(
                crate::daemon::ApiErrorCode::TlsRequired,
                "HTTPS is required for non-loopback connections",
            );
        }
    }
    next.run(request).await
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `proxy_mode` also trusts `cf-connecting-ip`, as `--remote` does.
    fn resolve(peer: &str, headers: &[(&'static str, &str)], proxy_mode: bool) -> Ingress {
        let mut map = HeaderMap::new();
        for (name, value) in headers {
            map.append(*name, value.parse().unwrap());
        }
        Ingress::resolve(
            SocketAddr::new(ip(peer), 4000),
            &map,
            proxy_mode,
            proxy_mode,
        )
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn forwarded_headers_count_only_from_a_loopback_peer_in_proxy_mode() {
        let forged = [
            ("cf-connecting-ip", "203.0.113.50"),
            ("x-forwarded-for", "203.0.113.50"),
            ("x-forwarded-proto", "https"),
        ];
        // Without proxy mode a loopback peer's headers assert nothing.
        let direct = resolve("127.0.0.1", &forged, false);
        assert_eq!(direct.client_ip, ip("127.0.0.1"));
        assert!(!direct.externally_secure && !direct.plaintext_remote);
        // A remote peer cannot assert TLS or identity in either mode.
        for proxy_mode in [false, true] {
            let remote = resolve("198.51.100.7", &forged, proxy_mode);
            assert_eq!(remote.client_ip, ip("198.51.100.7"));
            assert!(!remote.externally_secure);
            assert!(remote.plaintext_remote, "proxy_mode={proxy_mode}");
        }
        let proxied = resolve("127.0.0.1", &forged, true);
        assert_eq!(proxied.client_ip, ip("203.0.113.50"));
        assert!(proxied.externally_secure && !proxied.plaintext_remote);
        // Some proxies label a WebSocket upgrade `wss`, which is TLS; `ws` and `http` are not.
        for (proto, secure) in [("wss", true), ("WSS", true), ("ws", false), ("http", false)] {
            let ingress = resolve("127.0.0.1", &[("x-forwarded-proto", proto)], true);
            assert_eq!(ingress.externally_secure, secure, "{proto}");
            assert_eq!(ingress.plaintext_remote, !secure, "{proto}");
        }
        let remote = resolve("198.51.100.7", &[("x-forwarded-proto", "wss")], true);
        assert!(remote.plaintext_remote && !remote.externally_secure);
    }

    /// A proxy that names no client, or a malformed or repeated one, never keys login or
    /// rate limiting to the loopback peer.
    #[test]
    fn proxy_mode_never_keys_an_unnamed_client_to_the_loopback_peer() {
        for headers in [
            &[][..],
            &[("x-forwarded-for", "not-an-ip")],
            &[
                ("cf-connecting-ip", "not-an-ip"),
                ("x-forwarded-for", "203.0.113.5"),
            ],
            &[
                ("cf-connecting-ip", "203.0.113.5"),
                ("cf-connecting-ip", "203.0.113.6"),
            ],
        ] {
            assert_eq!(
                resolve("127.0.0.1", headers, true).client_ip,
                UNKNOWN_CLIENT
            );
        }
        assert_eq!(
            resolve(
                "127.0.0.1",
                &[("x-forwarded-for", "spoofed, 203.0.113.9")],
                true
            )
            .client_ip,
            ip("203.0.113.9"),
            "the last hop is the one the proxy appended"
        );
        assert_eq!(
            resolve(
                "127.0.0.1",
                &[
                    ("cf-connecting-ip", "203.0.113.50"),
                    ("x-forwarded-for", "10.0.0.1")
                ],
                true
            )
            .client_ip,
            ip("203.0.113.50")
        );
    }

    #[test]
    fn generic_proxy_mode_ignores_cf_connecting_ip() {
        let peer = SocketAddr::new(ip("127.0.0.1"), 4000);
        let mut headers = HeaderMap::new();
        headers.append("cf-connecting-ip", "203.0.113.50".parse().unwrap());
        assert_eq!(
            Ingress::resolve(peer, &headers, true, false).client_ip,
            UNKNOWN_CLIENT
        );
        headers.append("x-forwarded-for", "198.51.100.4".parse().unwrap());
        assert_eq!(
            Ingress::resolve(peer, &headers, true, false).client_ip,
            ip("198.51.100.4")
        );
    }

    #[test]
    fn plaintext_gate_applies_to_remote_peers_and_proxies_asserting_http() {
        let cases: &[(&str, &[(&'static str, &str)], bool, bool)] = &[
            // (peer, headers, proxy_mode, plaintext_remote)
            ("127.0.0.1", &[], false, false),
            ("127.0.0.1", &[], true, false),
            ("::1", &[], true, false),
            ("203.0.113.9", &[], false, true),
            ("203.0.113.9", &[("x-forwarded-proto", "https")], true, true),
            ("127.0.0.1", &[("x-forwarded-proto", "https")], true, false),
            ("127.0.0.1", &[("x-forwarded-proto", "HTTPS")], true, false),
            ("127.0.0.1", &[("x-forwarded-proto", "http")], true, true),
            (
                "127.0.0.1",
                &[("x-forwarded-proto", "http, https")],
                true,
                false,
            ),
            (
                "127.0.0.1",
                &[("x-forwarded-proto", "https, http")],
                true,
                true,
            ),
        ];
        for (peer, headers, proxy_mode, want) in cases {
            assert_eq!(
                resolve(peer, headers, *proxy_mode).plaintext_remote,
                *want,
                "{peer} {headers:?} proxy_mode={proxy_mode}"
            );
        }
    }


    #[test]
    fn private_network_covers_the_ranges_a_workspace_and_cityhall_share() {
        for private in [
            "127.0.0.1", "10.89.0.5", "172.16.0.1", "172.31.255.1", "192.168.1.9", "169.254.1.2",
            "100.64.0.1", "100.127.255.254", "::1", "fd00::5", "fe80::1",
        ] {
            assert!(is_private_network(ip(private)), "{private}");
        }
        for public in [
            "203.0.113.9", "8.8.8.8", "172.32.0.1", "100.128.0.1", "100.63.255.255", "2001:db8::1",
        ] {
            assert!(!is_private_network(ip(public)), "{public}");
        }
    }

    /// With the secret, a private-network peer is a trusted proxy: its forwarded client address
    /// is believed and plain HTTP over the hop is accepted. A public peer gains nothing.
    #[test]
    fn the_proxy_secret_makes_a_private_peer_trusted_but_never_a_public_one() {
        let peer = |addr: &str| SocketAddr::new(ip(addr), 4000);
        let mut headers = HeaderMap::new();
        headers.append("x-forwarded-for", "198.51.100.4".parse().unwrap());
        headers.append("x-forwarded-proto", "http".parse().unwrap());

        let trusted = Ingress::resolve_with_proxy_auth(peer("10.89.0.5"), &headers, true, false, true);
        assert!(!trusted.plaintext_remote);
        assert_eq!(trusted.client_ip, ip("198.51.100.4"));

        // No secret: a container-network peer is just a remote one.
        let anonymous = Ingress::resolve_with_proxy_auth(peer("10.89.0.5"), &headers, true, false, false);
        assert!(anonymous.plaintext_remote);
        assert_eq!(anonymous.client_ip, ip("10.89.0.5"));

        // The secret from the open internet: still plaintext-remote, forwarded address ignored.
        let public = Ingress::resolve_with_proxy_auth(peer("203.0.113.9"), &headers, true, false, true);
        assert!(public.plaintext_remote);
        assert_eq!(public.client_ip, ip("203.0.113.9"));
    }

    mod router {
        use std::net::SocketAddr;

        use axum::extract::ConnectInfo;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        use crate::daemon::ApiErrorCode;
        use crate::server::test_support::{build_router_for_test, build_test_app_state_ingress};

        const TOKEN: &str = "secret-token";

        async fn probe(
            state: std::sync::Arc<crate::server::AppState>,
            peer: &str,
            headers: &[(&str, &str)],
        ) -> (StatusCode, Option<ApiErrorCode>) {
            let mut builder = Request::builder().uri("/api/sessions");
            for (name, value) in headers {
                builder = builder.header(*name, *value);
            }
            let mut request = builder.body(axum::body::Body::empty()).unwrap();
            request.extensions_mut().insert(ConnectInfo(
                format!("{peer}:5555").parse::<SocketAddr>().unwrap(),
            ));
            let response = build_router_for_test(state).oneshot(request).await.unwrap();
            let code = ApiErrorCode::from_headers(response.status(), response.headers(), false);
            (response.status(), code)
        }

        const TLS_REQUIRED: (StatusCode, Option<ApiErrorCode>) = (
            StatusCode::UPGRADE_REQUIRED,
            Some(ApiErrorCode::TlsRequired),
        );

        /// Remote plaintext gets 426 before the Host gate and before auth, whatever it
        /// presents; loopback and an explicit opt-out reach the later gates.
        #[tokio::test]
        async fn remote_plaintext_is_rejected_before_host_and_auth_gates() {
            let strict = || build_test_app_state_ingress(Some(TOKEN.into()), None, false, false);
            let bearer = format!("Bearer {TOKEN}");
            for headers in [
                &[][..],
                &[("host", "evil.example")],
                &[("host", "localhost"), ("authorization", bearer.as_str())],
            ] {
                assert_eq!(probe(strict(), "203.0.113.9", headers).await, TLS_REQUIRED);
            }
            let (status, code) = probe(strict(), "127.0.0.1", &[("host", "localhost")]).await;
            assert_eq!((status, code), (StatusCode::UNAUTHORIZED, None));
            let opted_out = build_test_app_state_ingress(Some(TOKEN.into()), None, false, true);
            let (status, _) = probe(opted_out, "203.0.113.9", &[("host", "localhost")]).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED);
        }

        const PROXY_SECRET: &str = "workspace-proxy-secret";

        fn proxy_state() -> std::sync::Arc<crate::server::AppState> {
            crate::server::test_support::build_test_app_state_cityhall_proxy(PROXY_SECRET)
        }

        const PROXY_AUTH_REQUIRED: (StatusCode, Option<ApiErrorCode>) = (
            StatusCode::UNAUTHORIZED,
            Some(ApiErrorCode::ProxyAuthRequired),
        );

        /// In CityHall mode with a secret, the network reaches the workspace only through
        /// requests that carry it; the workspace's own loopback does not need it.
        #[tokio::test]
        async fn a_cityhall_workspace_rejects_network_callers_without_the_secret() {
            let host = ("host", "localhost");
            assert_eq!(probe(proxy_state(), "10.89.0.5", &[host]).await, PROXY_AUTH_REQUIRED);
            assert_eq!(
                probe(proxy_state(), "10.89.0.5", &[host, ("x-cityhall-proxy-token", "wrong")]).await,
                PROXY_AUTH_REQUIRED
            );
            // A repeated header is ambiguous and refused even when one value is right.
            assert_eq!(
                probe(
                    proxy_state(),
                    "10.89.0.5",
                    &[
                        host,
                        ("x-cityhall-proxy-token", PROXY_SECRET),
                        ("x-cityhall-proxy-token", PROXY_SECRET),
                    ]
                )
                .await,
                PROXY_AUTH_REQUIRED
            );
            // A public caller without it is refused too, before the plaintext gate.
            assert_eq!(probe(proxy_state(), "203.0.113.9", &[host]).await, PROXY_AUTH_REQUIRED);
            // Local processes inside the workspace do not need it.
            let (status, code) = probe(proxy_state(), "127.0.0.1", &[host]).await;
            assert_ne!(code, Some(ApiErrorCode::ProxyAuthRequired));
            assert_ne!(status, StatusCode::UPGRADE_REQUIRED);
        }

        /// The secret over a private hop is accepted even when CityHall says the end user
        /// was on plain HTTP; over a public address it still needs TLS.
        #[tokio::test]
        async fn the_secret_opens_a_private_hop_but_not_a_public_one() {
            let headers = [
                ("host", "localhost"),
                ("x-cityhall-proxy-token", PROXY_SECRET),
                ("x-forwarded-proto", "http"),
            ];
            let (status, code) = probe(proxy_state(), "10.89.0.5", &headers).await;
            assert_ne!(status, StatusCode::UPGRADE_REQUIRED, "private hop must pass the plaintext gate");
            assert_ne!(code, Some(ApiErrorCode::ProxyAuthRequired));
            assert_eq!(probe(proxy_state(), "203.0.113.9", &headers).await, TLS_REQUIRED);
        }

        /// Without a configured secret nothing about the old behaviour changes.
        #[tokio::test]
        async fn without_a_configured_secret_a_presented_one_changes_nothing() {
            let strict = build_test_app_state_ingress(Some(TOKEN.into()), None, true, false);
            let headers = [("host", "localhost"), ("x-cityhall-proxy-token", PROXY_SECRET)];
            assert_eq!(probe(strict, "10.89.0.5", &headers).await, TLS_REQUIRED);
        }

        #[tokio::test]
        async fn only_a_trusted_proxy_can_assert_https() {
            let proxy = || build_test_app_state_ingress(Some(TOKEN.into()), None, true, false);
            let https = [("host", "localhost"), ("x-forwarded-proto", "https")];
            // A remote peer's assertion is ignored, with or without proxy mode.
            assert_eq!(probe(proxy(), "203.0.113.9", &https).await, TLS_REQUIRED);
            let plain = build_test_app_state_ingress(Some(TOKEN.into()), None, false, false);
            assert_eq!(probe(plain, "203.0.113.9", &https).await, TLS_REQUIRED);
            // The loopback proxy's assertion passes the gate and lands on auth.
            let (status, _) = probe(proxy(), "127.0.0.1", &https).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED);
            // A trusted proxy that says the client used plain HTTP is not exempt.
            let http = [("host", "localhost"), ("x-forwarded-proto", "http")];
            assert_eq!(probe(proxy(), "127.0.0.1", &http).await, TLS_REQUIRED);
        }
    }
}
