//! Account-vouched pairing on the device (protocol 8): the checks of 8.5 on a `pair.approved`,
//! and the approver's statement, once for every product.
//!
//! The security of vouching lives in these checks, so products do not write them themselves.
//! A product keeps its trust list, its revoked set, its consumed approvals and its pairing
//! requests, and answers questions about them through [`TrustView`]; [`check`] says whether an
//! approval applies and what exactly to store. The product then stores it in one step:
//! [`Applicable::additions`] (possibly none) and [`Applicable::consumed`] together, so that an
//! approval is never applied twice (8.5, "Once only").
//!
//! ```text
//! let applicable = approval::check(&signed, &my_trust_list, &context)?;
//! if applicable.needs_user { /* show it as a notice; on "accept", store as below */ }
//! trust_list.add_all(applicable.additions);
//! trust_list.consume(applicable.consumed);
//! ```

use iroh::{EndpointId, SecretKey};

use crate::protocol::{
    DeviceId, Signed, Statement, limits,
    name::check_statement_name,
    statement::{DeviceSummary, Introduced, PairApproval},
};

/// Clock skew allowed on `issued_at` and kept on top of `expires_at`, in seconds (8.5).
pub const SKEW_SECS: i64 = 10 * 60;

/// How a trust-list entry was added (8.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    /// The 6-digit comparison on the LAN. Entries without a method count as this.
    LanSas,
    /// The 6-digit comparison over a remote connection (8.2).
    RemoteSas,
    /// In person, by QR or invite code.
    InPerson,
    /// Added because a direct pairing approved it (8.5).
    Vouched,
}

impl Method {
    /// The wire and storage name: `lan-sas`, `remote-sas`, `in-person` or `vouched`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LanSas => "lan-sas",
            Self::RemoteSas => "remote-sas",
            Self::InPerson => "in-person",
            Self::Vouched => "vouched",
        }
    }
}

/// What [`check`] needs to know of one trust-list entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrustEntry {
    /// How it was added.
    pub method: Method,
    /// "One of my devices" (8.1): may reach this device remotely and may vouch.
    pub remote: bool,
    /// The peer may control this device.
    pub allow_incoming: bool,
    /// This device may control the peer.
    pub allow_outgoing: bool,
}

/// The product's view of its own state, which [`check`] asks.
pub trait TrustView {
    /// The trust-list entry for `key`.
    fn entry(&self, key: &EndpointId) -> Option<TrustEntry>;

    /// Whether `key` is in the revoked set (9.3).
    fn is_revoked(&self, key: &EndpointId) -> bool;

    /// Whether `(approver, request_nonce)` is in the set of consumed approvals (8.5, check 9).
    fn is_consumed(&self, approver: &EndpointId, request_nonce: &str) -> bool;

    /// For the newcomer N (8.5, check 5): whether N sent the pairing request with
    /// `request_nonce` and still keeps it, and N's user confirmed the `remote-sas` pairing with
    /// `approver` for that request (8.2 step 3). False for every nonce N does not know.
    fn confirmed_request(&self, request_nonce: &str, approver: &EndpointId) -> bool;

    /// Whether the local policy accepts vouched devices on its own (8.5, check 8).
    fn accepts_vouched(&self) -> bool;
}

/// Who checks: this device, its server and its account.
#[derive(Debug, Clone, Copy)]
pub struct Context<'a> {
    /// This device's key.
    pub me: EndpointId,
    /// The server origin this device talks to (protocol 2.1).
    pub server: &'a str,
    /// This device's account (username).
    pub account: &'a str,
    /// Now, UNIX seconds, by this device's clock.
    pub now: i64,
}

/// Why an approval does not apply. The product logs it and drops the approval (8.5).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Refusal {
    /// The signature does not hold, or the statement is not a `pair-approval` (check 1).
    #[error("the approval does not verify")]
    Signature,
    /// It names another server or account (check 2).
    #[error("the approval is for another server or account")]
    OtherAccount,
    /// The approver is not a direct pairing of this device that is marked as one of the user's
    /// devices (check 3).
    #[error("the approver may not vouch on this device")]
    ApproverCannotVouch,
    /// The approver is revoked (check 4).
    #[error("the approver was revoked")]
    ApproverRevoked,
    /// This device is neither introduced nor the newcomer of a request it confirmed (check 5).
    #[error("the approval is not for this device")]
    NotForThisDevice,
    /// The newcomer or an introduced device is revoked, or is this device where it must not be
    /// (check 6).
    #[error("the approval names a revoked device or this device itself")]
    RevokedOrSelf,
    /// Outside its validity (check 7).
    #[error("the approval is not valid now")]
    NotValidNow,
    /// Already applied or dismissed once (check 9).
    #[error("the approval was already used")]
    Consumed,
    /// A name breaks the rules of protocol 2.1, or the statement is malformed.
    #[error("the approval is malformed: {0}")]
    Malformed(&'static str),
}

/// A trust-list entry to add.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Addition {
    /// The peer.
    pub endpoint_id: EndpointId,
    /// Its name as the approval gives it (protocol 2.1 holds for it).
    pub name: String,
    /// The peer may control this device, capped by the approver's own right (8.5).
    pub allow_incoming: bool,
    /// This device may control the peer, capped by the approver's own right (8.5).
    pub allow_outgoing: bool,
    /// Always [`Method::Vouched`].
    pub method: Method,
    /// The approver.
    pub vouched_by: EndpointId,
    /// The nonce of the request.
    pub request_nonce: String,
    /// Always true: vouched devices are the user's devices (8.1).
    pub remote: bool,
}

/// The entry of the consumed approvals to store with the additions (8.1, 8.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Consumed {
    /// The approver.
    pub approver: EndpointId,
    /// The nonce of the request.
    pub request_nonce: String,
    /// Keep it until then (UNIX seconds): the approval's `expires_at` plus [`SKEW_SECS`].
    pub keep_until: i64,
}

/// An approval that passed every check, and what applying it stores.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Applicable {
    /// The approval.
    pub approval: PairApproval,
    /// The entries to add: none when every named key already has an entry, which an approval
    /// never changes (8.5, "Only additions").
    pub additions: Vec<Addition>,
    /// Store this with the additions, and also when the user dismisses the notice.
    pub consumed: Consumed,
    /// The local policy does not accept vouched devices on its own (check 8): show the
    /// approval as a notice, and apply it only if the user accepts.
    pub needs_user: bool,
}

/// Runs the checks of protocol 8.5 on `signed`, a `pair.approved` that this device received,
/// and works out what applying it adds. The product shows a notice naming the approver for
/// every addition (threat model C10).
pub fn check(
    signed: &Signed,
    view: &dyn TrustView,
    context: &Context<'_>,
) -> Result<Applicable, Refusal> {
    // 1. The signature, over the approver the statement names.
    let Ok(Statement::PairApproval(approval)) = signed.open() else {
        return Err(Refusal::Signature);
    };
    // 2. This server and this account.
    if approval.server != context.server || approval.account != context.account {
        return Err(Refusal::OtherAccount);
    }
    check_statement_name(&approval.subject.name)
        .map_err(|_| Refusal::Malformed("the newcomer's name"))?;
    if approval
        .introduced
        .iter()
        .any(|device| check_statement_name(&device.name).is_err())
    {
        return Err(Refusal::Malformed("an introduced device's name"));
    }
    let approver = approval.approver.0;
    let newcomer = approval.subject.endpoint_id.0;
    if approval
        .introduced
        .iter()
        .any(|device| device.endpoint_id.0 == newcomer)
    {
        return Err(Refusal::Malformed("the newcomer is introduced to itself"));
    }
    // 3. A direct pairing that the user marked as one of their own devices; one level deep.
    let Some(approver_entry) = view
        .entry(&approver)
        .filter(|entry| entry.method != Method::Vouched && entry.remote)
    else {
        return Err(Refusal::ApproverCannotVouch);
    };
    // 4. Not revoked.
    if view.is_revoked(&approver) {
        return Err(Refusal::ApproverRevoked);
    }
    // 5. and 6. This device's role.
    let me = context.me;
    let introduced_me: Vec<&Introduced> = approval
        .introduced
        .iter()
        .filter(|device| device.endpoint_id.0 == me)
        .collect();
    let mut additions = Vec::new();
    if newcomer == me {
        // The newcomer N: its own request, confirmed by its user with this approver.
        if !introduced_me.is_empty() || !view.confirmed_request(&approval.request_nonce, &approver)
        {
            return Err(Refusal::NotForThisDevice);
        }
        for device in &approval.introduced {
            let key = device.endpoint_id.0;
            if view.is_revoked(&key) {
                return Err(Refusal::RevokedOrSelf);
            }
            // The approver listing itself, or a device N already trusts: no change.
            if view.entry(&key).is_some() {
                continue;
            }
            // Seen from N, the flags are the other way round (8.4), each capped by N's entry
            // for the approver.
            additions.push(addition(
                &approval,
                device.endpoint_id,
                &device.name,
                device.allow_outgoing && approver_entry.allow_incoming,
                device.allow_incoming && approver_entry.allow_outgoing,
            ));
        }
    } else {
        // An introduced device T.
        let [mine] = introduced_me.as_slice() else {
            return Err(if introduced_me.is_empty() {
                Refusal::NotForThisDevice
            } else {
                Refusal::Malformed("this device is introduced twice")
            });
        };
        if view.is_revoked(&newcomer) {
            return Err(Refusal::RevokedOrSelf);
        }
        if view.entry(&newcomer).is_none() {
            additions.push(addition(
                &approval,
                approval.subject.endpoint_id,
                &approval.subject.name,
                mine.allow_incoming && approver_entry.allow_incoming,
                mine.allow_outgoing && approver_entry.allow_outgoing,
            ));
        }
    }
    // 7. Valid now, allowing for clock skew.
    if context.now >= approval.expires_at || context.now < approval.issued_at - SKEW_SECS {
        return Err(Refusal::NotValidNow);
    }
    // 9. Never twice.
    if view.is_consumed(&approver, &approval.request_nonce) {
        return Err(Refusal::Consumed);
    }
    let consumed = Consumed {
        approver,
        request_nonce: approval.request_nonce.clone(),
        keep_until: approval.expires_at.saturating_add(SKEW_SECS),
    };
    Ok(Applicable {
        // 8. The local policy.
        needs_user: !view.accepts_vouched(),
        approval,
        additions,
        consumed,
    })
}

/// Signs the approval of approver `key` (protocol 8.4), once the comparison with the newcomer
/// passed and the user chose the devices to introduce and their directions (8.2 step 4).
/// `valid_secs` is capped at 30 days.
pub fn sign(
    key: &SecretKey,
    context: &Context<'_>,
    subject: DeviceSummary,
    request_nonce: &str,
    introduced: Vec<Introduced>,
    valid_secs: i64,
) -> Signed {
    let approval = PairApproval {
        server: context.server.to_owned(),
        account: context.account.to_owned(),
        approver: DeviceId(key.public()),
        subject,
        request_nonce: request_nonce.to_owned(),
        method: Method::RemoteSas.as_str().to_owned(),
        introduced,
        issued_at: context.now,
        expires_at: context
            .now
            .saturating_add(valid_secs.clamp(1, limits::MAX_APPROVAL_SECS)),
    };
    Signed::sign(&Statement::PairApproval(approval), key)
}

fn addition(
    approval: &PairApproval,
    endpoint_id: DeviceId,
    name: &str,
    allow_incoming: bool,
    allow_outgoing: bool,
) -> Addition {
    Addition {
        endpoint_id: endpoint_id.0,
        name: name.to_owned(),
        allow_incoming,
        allow_outgoing,
        method: Method::Vouched,
        vouched_by: approval.approver.0,
        request_nonce: approval.request_nonce.clone(),
        remote: true,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet};

    use super::*;

    const SERVER: &str = "https://cloud.example.com";
    const NOW: i64 = 1_763_200_200;
    const NONCE: &str = "bm9uY2Utb2YtdGhlLXJlcXVlc3Q";

    fn key(seed: u8) -> SecretKey {
        SecretKey::from_bytes(&[seed; 32])
    }

    /// A trust list in memory.
    #[derive(Default)]
    struct View {
        entries: HashMap<EndpointId, TrustEntry>,
        revoked: HashSet<EndpointId>,
        consumed: HashSet<(EndpointId, String)>,
        confirmed: HashSet<(String, EndpointId)>,
        refuse_vouched: bool,
    }

    impl TrustView for View {
        fn entry(&self, key: &EndpointId) -> Option<TrustEntry> {
            self.entries.get(key).copied()
        }
        fn is_revoked(&self, key: &EndpointId) -> bool {
            self.revoked.contains(key)
        }
        fn is_consumed(&self, approver: &EndpointId, request_nonce: &str) -> bool {
            self.consumed
                .contains(&(*approver, request_nonce.to_owned()))
        }
        fn confirmed_request(&self, request_nonce: &str, approver: &EndpointId) -> bool {
            self.confirmed
                .contains(&(request_nonce.to_owned(), *approver))
        }
        fn accepts_vouched(&self) -> bool {
            !self.refuse_vouched
        }
    }

    fn direct(method: Method, allow_incoming: bool, allow_outgoing: bool) -> TrustEntry {
        TrustEntry {
            method,
            remote: true,
            allow_incoming,
            allow_outgoing,
        }
    }

    fn summary(key: &SecretKey, name: &str) -> DeviceSummary {
        DeviceSummary {
            endpoint_id: DeviceId(key.public()),
            name: name.to_owned(),
            platform: "windows".to_owned(),
            product: "input-show".to_owned(),
        }
    }

    fn context(me: &SecretKey) -> Context<'static> {
        Context {
            me: me.public(),
            server: SERVER,
            account: "kim",
            now: NOW,
        }
    }

    /// Phone A approves Work PC N for Home PC T: N may control T, T may not control N.
    fn approval_by(approver: &SecretKey, newcomer: &SecretKey, targets: &[&SecretKey]) -> Signed {
        let introduced = targets
            .iter()
            .map(|target| Introduced {
                endpoint_id: DeviceId(target.public()),
                name: "Home PC".to_owned(),
                allow_incoming: true,
                allow_outgoing: false,
            })
            .collect();
        sign(
            approver,
            &context(approver),
            summary(newcomer, "Work PC"),
            NONCE,
            introduced,
            30 * 24 * 60 * 60,
        )
    }

    /// The approver A (1), the newcomer N (2) and the target T (3), and T's trust list with A.
    fn target_view() -> (SecretKey, SecretKey, SecretKey, View) {
        let (a, n, t) = (key(1), key(2), key(3));
        let mut view = View::default();
        view.entries
            .insert(a.public(), direct(Method::LanSas, true, true));
        (a, n, t, view)
    }

    #[test]
    fn the_target_adds_the_newcomer_with_the_named_directions() {
        let (a, n, t, view) = target_view();
        let applicable = check(&approval_by(&a, &n, &[&t]), &view, &context(&t)).unwrap();
        assert!(!applicable.needs_user);
        assert_eq!(applicable.additions.len(), 1);
        let added = &applicable.additions[0];
        assert_eq!(added.endpoint_id, n.public());
        assert_eq!(added.name, "Work PC");
        assert!(added.allow_incoming, "N may control T");
        assert!(!added.allow_outgoing, "T may not control N");
        assert_eq!(added.method, Method::Vouched);
        assert_eq!(added.vouched_by, a.public());
        assert!(added.remote);
        assert_eq!(applicable.consumed.approver, a.public());
        assert_eq!(applicable.consumed.request_nonce, NONCE);
        assert_eq!(
            applicable.consumed.keep_until,
            NOW + 30 * 24 * 60 * 60 + SKEW_SECS
        );
    }

    #[test]
    fn the_newcomer_adds_the_introduced_devices_the_other_way_round() {
        let (a, n, t) = (key(1), key(2), key(3));
        let mut view = View::default();
        view.entries
            .insert(a.public(), direct(Method::RemoteSas, true, true));
        view.confirmed.insert((NONCE.to_owned(), a.public()));
        let applicable = check(&approval_by(&a, &n, &[&t]), &view, &context(&n)).unwrap();
        let added = &applicable.additions[0];
        assert_eq!(added.endpoint_id, t.public());
        assert!(!added.allow_incoming, "T may not control N");
        assert!(added.allow_outgoing, "N may control T");
    }

    #[test]
    fn the_newcomer_needs_its_own_confirmed_request() {
        // Without the user's confirmation on N (protocol 8.2 step 3), a server that paired its
        // own key with N could get anything applied (review F-02).
        let (a, n, t) = (key(1), key(2), key(3));
        let mut view = View::default();
        view.entries
            .insert(a.public(), direct(Method::RemoteSas, true, true));
        assert_eq!(
            check(&approval_by(&a, &n, &[&t]), &view, &context(&n)),
            Err(Refusal::NotForThisDevice)
        );
        // Confirmed with another approver.
        view.confirmed.insert((NONCE.to_owned(), key(9).public()));
        assert_eq!(
            check(&approval_by(&a, &n, &[&t]), &view, &context(&n)),
            Err(Refusal::NotForThisDevice)
        );
    }

    #[test]
    fn flags_are_capped_by_the_approvers_own_rights() {
        // The phone may not control the home PC, so it cannot let the newcomer do so (F-08).
        let (a, n, t, mut view) = target_view();
        view.entries
            .insert(a.public(), direct(Method::LanSas, false, true));
        let applicable = check(&approval_by(&a, &n, &[&t]), &view, &context(&t)).unwrap();
        assert!(!applicable.additions[0].allow_incoming);
    }

    #[test]
    fn existing_entries_are_never_changed() {
        let (a, n, t, mut view) = target_view();
        view.entries
            .insert(n.public(), direct(Method::LanSas, false, false));
        let applicable = check(&approval_by(&a, &n, &[&t]), &view, &context(&t)).unwrap();
        assert!(applicable.additions.is_empty());
    }

    #[test]
    fn a_consumed_approval_never_applies_again() {
        // The user removed the vouched entry; the server delivers the approval again (F-07).
        let (a, n, t, mut view) = target_view();
        view.consumed.insert((a.public(), NONCE.to_owned()));
        assert_eq!(
            check(&approval_by(&a, &n, &[&t]), &view, &context(&t)),
            Err(Refusal::Consumed)
        );
    }

    #[test]
    fn the_approver_must_be_a_direct_pairing_marked_as_the_users_own() {
        let (a, n, t, mut view) = target_view();
        for entry in [
            direct(Method::Vouched, true, true),
            TrustEntry {
                remote: false,
                ..direct(Method::LanSas, true, true)
            },
        ] {
            view.entries.insert(a.public(), entry);
            assert_eq!(
                check(&approval_by(&a, &n, &[&t]), &view, &context(&t)),
                Err(Refusal::ApproverCannotVouch),
                "{entry:?}"
            );
        }
        view.entries.remove(&a.public());
        assert_eq!(
            check(&approval_by(&a, &n, &[&t]), &view, &context(&t)),
            Err(Refusal::ApproverCannotVouch)
        );
    }

    #[test]
    fn revoked_keys_are_refused() {
        let (a, n, t, mut view) = target_view();
        view.revoked.insert(a.public());
        assert_eq!(
            check(&approval_by(&a, &n, &[&t]), &view, &context(&t)),
            Err(Refusal::ApproverRevoked)
        );
        let (a, n, t, mut view) = target_view();
        view.revoked.insert(n.public());
        assert_eq!(
            check(&approval_by(&a, &n, &[&t]), &view, &context(&t)),
            Err(Refusal::RevokedOrSelf)
        );
    }

    #[test]
    fn other_devices_servers_accounts_and_times_are_refused() {
        let (a, n, t, view) = target_view();
        let signed = approval_by(&a, &n, &[&t]);
        assert_eq!(
            check(&signed, &view, &context(&key(4))),
            Err(Refusal::NotForThisDevice)
        );
        let other_server = Context {
            server: "https://other.example.com",
            ..context(&t)
        };
        assert_eq!(
            check(&signed, &view, &other_server),
            Err(Refusal::OtherAccount)
        );
        let other_account = Context {
            account: "sam",
            ..context(&t)
        };
        assert_eq!(
            check(&signed, &view, &other_account),
            Err(Refusal::OtherAccount)
        );
        for now in [NOW - SKEW_SECS - 1, NOW + 30 * 24 * 60 * 60] {
            let at = Context { now, ..context(&t) };
            assert_eq!(
                check(&signed, &view, &at),
                Err(Refusal::NotValidNow),
                "{now}"
            );
        }
        let skewed = Context {
            now: NOW - SKEW_SECS + 1,
            ..context(&t)
        };
        assert!(check(&signed, &view, &skewed).is_ok());
    }

    #[test]
    fn a_forged_signature_and_bad_names_are_refused() {
        let (a, n, t, view) = target_view();
        let mut forged = approval_by(&a, &n, &[&t]);
        forged.signature = approval_by(&key(5), &n, &[&t]).signature;
        assert_eq!(check(&forged, &view, &context(&t)), Err(Refusal::Signature));

        let bidi = sign(
            &a,
            &context(&a),
            summary(&n, "Home \u{202E}CP"),
            NONCE,
            vec![Introduced {
                endpoint_id: DeviceId(t.public()),
                name: "Home PC".to_owned(),
                allow_incoming: true,
                allow_outgoing: false,
            }],
            3600,
        );
        assert!(matches!(
            check(&bidi, &view, &context(&t)),
            Err(Refusal::Malformed(_))
        ));

        // Statements travel unchanged, so a name with line breaks or padding at its edges is
        // refused rather than trimmed.
        let untrimmed = sign(
            &a,
            &context(&a),
            summary(&n, "Work PC\n\n\n"),
            NONCE,
            vec![Introduced {
                endpoint_id: DeviceId(t.public()),
                name: "Home PC".to_owned(),
                allow_incoming: true,
                allow_outgoing: false,
            }],
            3600,
        );
        assert_eq!(
            check(&untrimmed, &view, &context(&t)),
            Err(Refusal::Malformed("the newcomer's name"))
        );
    }

    #[test]
    fn with_the_policy_off_the_approval_waits_for_the_user() {
        let (a, n, t, mut view) = target_view();
        view.refuse_vouched = true;
        let applicable = check(&approval_by(&a, &n, &[&t]), &view, &context(&t)).unwrap();
        assert!(applicable.needs_user);
        assert_eq!(applicable.additions.len(), 1);
    }
}
