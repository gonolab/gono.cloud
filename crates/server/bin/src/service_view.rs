//! The services of an account as the pages show them (`gono_server_core::services`): their
//! names and descriptions in the page's language, whether this server offers them at all, and
//! whether the account has them.

use gono_server_core::services::{Service, Services};

use crate::{app::AppState, i18n::Text};

/// One service of one account, for a page.
#[derive(Debug, Clone)]
pub struct ServiceRow {
    /// The service's name in forms and URLs (`files`, `webdav`, ...).
    pub id: &'static str,
    /// Its name in the page's language.
    pub name: &'static str,
    /// What it allows, in the page's language.
    pub note: &'static str,
    /// The account has it.
    pub on: bool,
    /// This server offers it: the feature behind it is configured (the web file UI, the S3 API,
    /// remote connectivity). WebDAV is always offered.
    pub offered: bool,
}

/// The name of `service` in the language of `t`.
pub fn name(t: &Text, service: Service) -> &'static str {
    match service {
        Service::Files => t.svc_files,
        Service::Webdav => t.svc_webdav,
        Service::S3 => t.svc_s3,
        Service::Direct => t.svc_direct,
        Service::Relay => t.svc_relay,
    }
}

/// What `service` allows, in the language of `t`.
pub fn note(t: &Text, service: Service) -> &'static str {
    match service {
        Service::Files => t.svc_files_note,
        Service::Webdav => t.svc_webdav_note,
        Service::S3 => t.svc_s3_note,
        Service::Direct => t.svc_direct_note,
        Service::Relay => t.svc_relay_note,
    }
}

/// Whether this server offers `service`: an account that has it can use it only then.
pub fn offered(state: &AppState, service: Service) -> bool {
    match service {
        Service::Files => state.files.is_some(),
        Service::Webdav => true,
        Service::S3 => state.s3.is_some(),
        Service::Direct | Service::Relay => state.connect.is_some(),
    }
}

/// Every service, with whether `services` has it and whether this server offers it.
pub fn rows(t: &Text, state: &AppState, services: Services) -> Vec<ServiceRow> {
    Service::ALL
        .into_iter()
        .map(|service| ServiceRow {
            id: service.as_str(),
            name: name(t, service),
            note: note(t, service),
            on: services.has(service),
            offered: offered(state, service),
        })
        .collect()
}

/// The names of the services `services` has, separated by commas, or "None".
pub fn summary(t: &Text, services: Services) -> String {
    if services.is_none() {
        return t.svc_none.to_owned();
    }
    services
        .enabled()
        .map(|service| name(t, service))
        .collect::<Vec<_>>()
        .join(", ")
}
