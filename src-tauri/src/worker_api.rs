//! Cloudflare's API, for deploying and managing the user's Worker.
//!
//! A port of the Android client's `WorkerApi`: the same endpoints, the same
//! order of writes and the same recovery rules. The token is held only by the
//! value built for one command and is never written anywhere; errors that might
//! echo it are scrubbed before they leave this module.

use std::io::{Read, Write};
use std::net::SocketAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Serialize;
use serde_json::{json, Value};

use crate::worker::{hex32, random_uuid, valid_host, WorkerDeployment, WORKER_SCRIPT};

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct WorkerAccount {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Clone)]
pub struct ApiRequest {
    pub method: String,
    pub path: String,
    pub body: Option<Vec<u8>>,
    pub content_type: String,
}

impl ApiRequest {
    fn new(method: &str, path: &str, body: Option<Value>) -> Self {
        Self {
            method: method.into(),
            path: path.into(),
            body: body.map(|value| value.to_string().into_bytes()),
            content_type: "application/json".into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiError {
    pub status: u16,
    pub message: String,
}

impl From<String> for ApiError {
    fn from(message: String) -> Self {
        Self { status: 0, message }
    }
}

impl From<&str> for ApiError {
    fn from(message: &str) -> Self {
        Self { status: 0, message: message.into() }
    }
}

pub type Exchange = Box<dyn Fn(&str, &ApiRequest) -> Result<Value, ApiError> + Send + Sync>;
type ApiResult<T> = Result<T, ApiError>;

/// The dashboard form for a token with exactly the permissions this uses.
pub fn token_template_url() -> String {
    let groups = r#"[{"key":"account_settings","type":"read"},{"key":"workers_scripts","type":"edit"},{"key":"page","type":"edit"},{"key":"zone","type":"read"},{"key":"dns","type":"edit"},{"key":"account_analytics","type":"read"}]"#;
    format!(
        "https://dash.cloudflare.com/profile/api-tokens?permissionGroupKeys={}&accountId=*&zoneId=all&name=WhiteAesther",
        encode(groups)
    )
}

/// `application/x-www-form-urlencoded`, as Java's URLEncoder writes it.
pub(crate) fn encode(value: &str) -> String {
    let mut out = String::new();
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'.' | b'-' | b'*' | b'_' => out.push(byte as char),
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

pub struct WorkerApi {
    token: String,
    script: String,
    exchange: Exchange,
}

impl WorkerApi {
    /// The real API, through `carrier` when one is up and directly otherwise.
    pub fn new(token: &str, carrier: Option<SocketAddr>) -> ApiResult<Self> {
        Self::with_exchange(token, WORKER_SCRIPT, Box::new(move |token, request| request_https(carrier, token, request)))
    }

    pub fn with_exchange(token: &str, script: &str, exchange: Exchange) -> ApiResult<Self> {
        let token = token.trim().to_string();
        let shape = (30..=4096).contains(&token.len()) && token.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-');
        if !shape {
            return Err("Paste the API token itself, without quotes or a command".into());
        }
        Ok(Self { token, script: script.into(), exchange })
    }

    /// Removes the token from text that may have echoed it.
    pub fn scrub(&self, text: &str) -> String {
        text.replace(&self.token, "[token]")
    }

    /// One request, retried up to three times when Cloudflare's edge answers 502/503/504.
    fn call(&self, request: ApiRequest) -> ApiResult<Value> {
        let busy = |status: u64| matches!(status, 502..=504);
        let mut attempt = 1;
        loop {
            let answer = (self.exchange)(&self.token, &request);
            let status = match &answer {
                Ok(value) if value["success"] != true => value["httpStatus"].as_u64().unwrap_or(0),
                Err(error) => u64::from(error.status),
                Ok(_) => 0,
            };
            if !busy(status) || attempt == 3 {
                return answer.map_err(|error| ApiError { status: error.status, message: self.scrub(&error.message) });
            }
            #[cfg(not(test))]
            std::thread::sleep(Duration::from_secs(2 * attempt));
            attempt += 1;
        }
    }

    fn send(&self, method: &str, path: &str, body: Option<Value>) -> ApiResult<Value> {
        result(self.call(ApiRequest::new(method, path, body))?)
    }

    fn upload(&self, method: &str, path: &str, fields: &[(&str, &str)], file_name: &str) -> ApiResult<Value> {
        let mut all: Vec<(&str, &str)> = fields.to_vec();
        all.push((file_name, &self.script));
        result(self.call(multipart(method, path, &all, file_name))?)
    }

    pub fn accounts(&self) -> ApiResult<Vec<WorkerAccount>> {
        let mut accounts = Vec::new();
        let mut page = 1;
        loop {
            let response = self.call(ApiRequest::new("GET", &format!("/accounts?per_page=50&page={page}"), None))?;
            let total = response["result_info"]["total_pages"].as_u64().unwrap_or(1);
            let rows = result(response)?;
            let rows = rows.as_array().ok_or("Cloudflare did not return accounts")?;
            for row in rows {
                let id = row["id"].as_str().unwrap_or_default();
                if !hex32(id) {
                    return Err("Cloudflare returned an invalid account ID".into());
                }
                accounts.push(WorkerAccount { id: id.into(), name: row["name"].as_str().unwrap_or_default().into() });
            }
            page += 1;
            if page > total || page > 100 {
                return Ok(accounts);
            }
        }
    }

    pub fn deploy(&self, original: &WorkerDeployment, save: &dyn Fn(&WorkerDeployment) -> Result<(), String>) -> ApiResult<WorkerDeployment> {
        let mut deployment = WorkerDeployment { ready: false, ..original.clone() };
        deployment.validate()?;
        let base = format!("/accounts/{}", deployment.account_id);
        let date = COMPATIBILITY_DATE;
        if deployment.pages {
            let production = json!({
                "compatibility_date": date,
                "env_vars": { "ENV": { "type": "plain_text", "value": deployment.environment() } },
            });
            let body = json!({ "deployment_configs": { "production": production } });
            let patch = |body: Value| self.send("PATCH", &format!("{base}/pages/projects/{}", deployment.name), Some(body));
            let project = if !deployment.created {
                let mut create = body.clone();
                create["name"] = json!(deployment.name);
                create["production_branch"] = json!("main");
                match self.send("POST", &format!("{base}/pages/projects"), Some(create)) {
                    // An earlier attempt created it even though its answer was lost.
                    Err(error) if error.message.to_ascii_lowercase().contains("already exists") => patch(body)?,
                    other => other?,
                }
            } else {
                patch(body)?
            };
            let host = project["subdomain"].as_str().ok_or("Cloudflare did not return a Pages project")?;
            deployment.created = true;
            deployment.host = host.into();
            save(&deployment)?;
            self.upload(
                "POST",
                &format!("{base}/pages/projects/{}/deployments", deployment.name),
                &[("manifest", "{}"), ("branch", "main")],
                "_worker.js",
            )?;
        } else {
            let existing = match self.send("GET", &format!("{base}/workers/subdomain"), None) {
                Ok(value) => value["subdomain"].as_str().unwrap_or_default().to_string(),
                Err(error) if error.status == 404 || error.message.contains("10007") => String::new(),
                Err(error) => return Err(error),
            };
            let subdomain = if existing.is_empty() {
                let wanted = crate::worker::neutral_name();
                let registered = self.send("PUT", &format!("{base}/workers/subdomain"), Some(json!({ "subdomain": wanted })))?;
                registered["subdomain"].as_str().ok_or("Could not register workers.dev hostname")?.to_string()
            } else {
                existing
            };
            let metadata = json!({
                "main_module": "worker.js",
                "compatibility_date": date,
                "bindings": [{ "type": "plain_text", "name": "ENV", "text": deployment.environment() }],
            })
            .to_string();
            self.upload("PUT", &format!("{base}/workers/scripts/{}", deployment.name), &[("metadata", &metadata)], "worker.js")?;
            deployment.created = true;
            deployment.host = format!("{}.{subdomain}.workers.dev", deployment.name);
            save(&deployment)?;
            self.send(
                "POST",
                &format!("{base}/workers/scripts/{}/subdomain", deployment.name),
                Some(json!({ "enabled": true, "previews_enabled": false })),
            )?;
        }
        if !deployment.has_public_host() {
            return Err("The deployment has no valid public hostname yet".into());
        }
        deployment.ready = true;
        save(&deployment)?;
        Ok(deployment)
    }

    pub fn delete(&self, deployment: &WorkerDeployment) -> ApiResult<()> {
        if !deployment.custom_domain.is_empty() {
            self.detach_domain(deployment, &|_| Ok(()))?;
        }
        let kind = if deployment.pages { "pages/projects" } else { "workers/scripts" };
        gone(self.send("DELETE", &format!("/accounts/{}/{kind}/{}", deployment.account_id, deployment.name), None).map(|_| ()))
    }

    /// Every Worker script and Pages project in the account, including ones made elsewhere.
    // shortcut: reads the first page of each list (Cloudflare's default size), add paging if accounts grow past it.
    pub fn list_account(&self, account_id: &str) -> ApiResult<Vec<RemoteDeployment>> {
        if !hex32(account_id) {
            return Err("Invalid Cloudflare account".into());
        }
        let base = format!("/accounts/{account_id}");
        let subdomain = self
            .send("GET", &format!("{base}/workers/subdomain"), None)
            .map(|value| value["subdomain"].as_str().unwrap_or_default().to_string())
            .unwrap_or_default();
        let mut list = Vec::new();
        for row in self.send("GET", &format!("{base}/workers/scripts"), None)?.as_array().ok_or("Cloudflare did not return Worker scripts")? {
            let name = row["id"].as_str().unwrap_or_default().to_string();
            let host = if subdomain.is_empty() { String::new() } else { format!("{name}.{subdomain}.workers.dev") };
            list.push(RemoteDeployment { name, pages: false, host });
        }
        for row in self.send("GET", &format!("{base}/pages/projects"), None)?.as_array().ok_or("Cloudflare did not return Pages projects")? {
            let name = row["name"].as_str().unwrap_or_default().to_string();
            list.push(RemoteDeployment { name, pages: true, host: row["subdomain"].as_str().unwrap_or_default().into() });
        }
        list.retain(|item| valid_remote_name(&item.name));
        Ok(list)
    }

    /// Deletes a Worker script or Pages project by name; one that is already gone is not an error.
    pub fn delete_named(&self, account_id: &str, name: &str, pages: bool) -> ApiResult<()> {
        if !hex32(account_id) || !valid_remote_name(name) {
            return Err("Invalid Cloudflare deployment".into());
        }
        let kind = if pages { "pages/projects" } else { "workers/scripts" };
        gone(self.send("DELETE", &format!("/accounts/{account_id}/{kind}/{name}"), None).map(|_| ()))
    }

    pub fn attach_domain(
        &self,
        original: &WorkerDeployment,
        hostname: &str,
        save: &dyn Fn(&WorkerDeployment) -> Result<(), String>,
    ) -> ApiResult<WorkerDeployment> {
        if !original.ready {
            return Err("Finish deploying before attaching a domain".into());
        }
        let domain = hostname.trim().to_lowercase();
        let tld_letters = domain.rsplit('.').next().is_some_and(|tld| !tld.is_empty() && tld.chars().all(char::is_alphabetic));
        if domain.split('.').count() < 2 || !tld_letters || !valid_host(&domain) {
            return Err("Use a domain such as vpn.example.com".into());
        }
        if !original.custom_domain.is_empty() && original.custom_domain != domain {
            return Err("Detach the current domain before choosing another".into());
        }
        let mut deployment = WorkerDeployment { custom_domain: domain.clone(), domain_pending: true, ..original.clone() };
        save(&deployment)?;
        let base = format!("/accounts/{}", deployment.account_id);
        if !deployment.pages {
            let attached = self.send("GET", &format!("{base}/workers/domains?hostname={}", encode(&domain)), None)?;
            for existing in attached.as_array().ok_or("Cloudflare did not return Worker domains")? {
                if existing["hostname"] == domain.as_str() && existing["service"] != deployment.name.as_str() {
                    return Err("This domain belongs to another Worker; use an unused subdomain".into());
                }
            }
            let mut failure = String::new();
            for zone in zone_candidates(&domain) {
                let body = json!({ "hostname": domain, "service": deployment.name, "zone_name": zone });
                match self.send("PUT", &format!("{base}/workers/domains"), Some(body)) {
                    Ok(_) => {
                        deployment.domain_pending = false;
                        save(&deployment)?;
                        return Ok(deployment);
                    }
                    Err(error) if error.status == 401 || error.status == 403 => return Err(error),
                    Err(error) => failure = error.message,
                }
            }
            return Err(format!("The domain must belong to this Cloudflare account: {failure}").into());
        }
        let mut zone_id = deployment.dns_zone.clone();
        if zone_id.is_empty() {
            for zone in zone_candidates(&domain) {
                let zones = self.send("GET", &format!("/zones?account.id={}&name={}", deployment.account_id, encode(&zone)), None)?;
                let zones = zones.as_array().ok_or("Cloudflare did not return zones")?;
                if let Some(first) = zones.first() {
                    zone_id = first["id"].as_str().unwrap_or_default().into();
                    break;
                }
            }
            if !hex32(&zone_id) {
                return Err("No matching zone found; allow Zone: Read and DNS: Edit for your domain".into());
            }
            deployment.dns_zone = zone_id.clone();
            save(&deployment)?;
        }
        let records = self.send("GET", &format!("/zones/{zone_id}/dns_records?name={}", encode(&domain)), None)?;
        let mut existing_cname = false;
        for record in records.as_array().ok_or("Cloudflare did not return DNS records")? {
            let kind = record["type"].as_str().unwrap_or_default();
            if ["A", "AAAA", "CNAME"].contains(&kind) {
                if kind != "CNAME" || record["content"] != deployment.host.as_str() {
                    return Err("This hostname already has a DNS record; use an unused subdomain".into());
                }
                existing_cname = true;
            }
        }
        if !existing_cname {
            let body = json!({ "type": "CNAME", "name": domain, "content": deployment.host, "proxied": true, "ttl": 1 });
            let record = self.send("POST", &format!("/zones/{zone_id}/dns_records"), Some(body))?;
            deployment.dns_record = record["id"].as_str().ok_or("Cloudflare did not return the new DNS record")?.into();
            save(&deployment)?;
        }
        let domains = self.send("GET", &format!("{base}/pages/projects/{}/domains", deployment.name), None)?;
        let domains = domains.as_array().ok_or("Cloudflare did not return Pages domains")?;
        if !domains.iter().any(|d| d["name"] == domain.as_str()) {
            self.send("POST", &format!("{base}/pages/projects/{}/domains", deployment.name), Some(json!({ "name": domain })))?;
        }
        deployment.domain_pending = false;
        save(&deployment)?;
        Ok(deployment)
    }

    pub fn detach_domain(
        &self,
        original: &WorkerDeployment,
        save: &dyn Fn(&WorkerDeployment) -> Result<(), String>,
    ) -> ApiResult<WorkerDeployment> {
        if original.custom_domain.is_empty() {
            return Ok(original.clone());
        }
        let deployment = original;
        let domain = encode(&deployment.custom_domain);
        let base = format!("/accounts/{}", deployment.account_id);
        if deployment.pages {
            gone(self.send("DELETE", &format!("{base}/pages/projects/{}/domains/{domain}", deployment.name), None).map(|_| ()))?;
            if !deployment.dns_zone.is_empty() && !deployment.dns_record.is_empty() {
                let path = format!("/zones/{}/dns_records/{}", deployment.dns_zone, deployment.dns_record);
                gone((|| {
                    let record = self.send("GET", &path, None)?;
                    // A changed record belongs to the operator now; never delete it.
                    if record["name"] == deployment.custom_domain.as_str()
                        && record["type"] == "CNAME"
                        && record["content"] == deployment.host.as_str()
                    {
                        self.send("DELETE", &path, None)?;
                    }
                    Ok(())
                })())?;
            }
        } else {
            let records = self.send("GET", &format!("{base}/workers/domains?hostname={domain}&service={}", deployment.name), None)?;
            for record in records.as_array().ok_or("Cloudflare did not return Worker domains")? {
                if record["hostname"] == deployment.custom_domain.as_str() && record["service"] == deployment.name.as_str() {
                    let id = record["id"].as_str().unwrap_or_default();
                    if !hex32(id) {
                        return Err("Cloudflare returned an invalid domain ID".into());
                    }
                    gone(self.send("DELETE", &format!("{base}/workers/domains/{id}"), None).map(|_| ()))?;
                }
            }
        }
        let detached = WorkerDeployment {
            custom_domain: String::new(),
            domain_pending: false,
            dns_zone: String::new(),
            dns_record: String::new(),
            ..deployment.clone()
        };
        save(&detached)?;
        Ok(detached)
    }

    /// Requests over the last 24 hours: (whole account, this Worker).
    pub fn usage(&self, deployment: &WorkerDeployment) -> ApiResult<(u64, u64)> {
        if deployment.pages {
            return Err("Worker request analytics do not apply to Pages deployments".into());
        }
        let end = now_secs();
        let query = "query Usage($account: String!, $script: String!, $start: String!, $end: String!) {
            viewer { accounts(filter: {accountTag: $account}) {
                total: workersInvocationsAdaptive(limit: 100, filter: {datetime_geq: $start, datetime_leq: $end}) { sum { requests } }
                worker: workersInvocationsAdaptive(limit: 100, filter: {scriptName: $script, datetime_geq: $start, datetime_leq: $end}) { sum { requests } }
            }} }";
        let body = json!({
            "query": query,
            "variables": { "account": deployment.account_id, "script": deployment.name, "start": utc_instant(end - 86_400), "end": utc_instant(end) },
        });
        let response = self.call(ApiRequest::new("POST", "/graphql", Some(body)))?;
        let failed = response["errors"].as_array().is_some_and(|e| !e.is_empty())
            || !(200..300).contains(&response["httpStatus"].as_u64().unwrap_or(200));
        if failed {
            return Err("Usage query failed; allow Account Analytics: Read".into());
        }
        let account = &response["data"]["viewer"]["accounts"][0];
        if account.is_null() {
            return Err("No account usage data was returned".into());
        }
        let sum = |key: &str| {
            account[key].as_array().map_or(0, |rows| rows.iter().map(|row| row["sum"]["requests"].as_u64().unwrap_or(0)).sum())
        };
        Ok((sum("total"), sum("worker")))
    }
}

/// A Worker script or Pages project found in the account.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct RemoteDeployment {
    pub name: String,
    pub pages: bool,
    pub host: String,
}

/// Script and project names go into API paths, so only Cloudflare's own name characters pass.
fn valid_remote_name(name: &str) -> bool {
    (1..=63).contains(&name.len()) && name.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
}

fn gone(outcome: ApiResult<()>) -> ApiResult<()> {
    match outcome {
        Err(error) if error.status == 404 => Ok(()),
        other => other,
    }
}

fn zone_candidates(hostname: &str) -> Vec<String> {
    let labels: Vec<&str> = hostname.split('.').collect();
    (0..labels.len().saturating_sub(1)).map(|i| labels[i..].join(".")).collect()
}

fn result(response: Value) -> ApiResult<Value> {
    if response["success"].as_bool() != Some(true) {
        let message = response["errors"]
            .as_array()
            .map(|errors| {
                errors
                    .iter()
                    .map(|e| format!("{} ({})", e["message"].as_str().unwrap_or_default(), e["code"].as_i64().unwrap_or(0)))
                    .collect::<Vec<_>>()
                    .join("; ")
            })
            .unwrap_or_default();
        let message = if message.trim().is_empty() { "Cloudflare rejected the request".to_string() } else { message };
        return Err(ApiError { status: response["httpStatus"].as_u64().unwrap_or(0) as u16, message: message.chars().take(1000).collect() });
    }
    Ok(response.get("result").cloned().unwrap_or(Value::Null))
}

pub(crate) fn multipart(method: &str, path: &str, fields: &[(&str, &str)], file_name: &str) -> ApiRequest {
    let boundary = format!("whiteaesther-{}", random_uuid());
    let mut body = Vec::new();
    for (name, value) in fields {
        let file = *name == file_name;
        let filename = if file { format!("; filename=\"{file_name}\"") } else { String::new() };
        let kind = if file { "application/javascript+module" } else { "application/json" };
        body.extend_from_slice(
            format!("--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"{filename}\r\nContent-Type: {kind}\r\n\r\n{value}\r\n").as_bytes(),
        );
    }
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    ApiRequest { method: method.into(), path: path.into(), body: Some(body), content_type: format!("multipart/form-data; boundary={boundary}") }
}

/// A fixed runtime date the script was tested on end to end. "Today" can be newer than a
/// Cloudflare runtime supports, and a Worker that cannot load answers every request
/// with error 1101.
const COMPATIBILITY_DATE: &str = "2026-10-01";

const API_HOST: &str = "api.cloudflare.com";
const MAX_RESPONSE: usize = 2_000_000;

fn request_https(carrier: Option<SocketAddr>, token: &str, request: &ApiRequest) -> Result<Value, ApiError> {
    let allowed = ["/accounts", "/zones", "/graphql"].iter().any(|prefix| request.path.starts_with(prefix));
    if !allowed || request.path.contains("..") || request.path.contains(['\r', '\n', ' ']) {
        return Err("Refusing an unexpected Cloudflare API path".into());
    }
    let mut stream = crate::tls::connect_verified(carrier, API_HOST, 443, Duration::from_secs(90))?;
    let body = request.body.as_deref().unwrap_or_default();
    let mut head = format!(
        "{} /client/v4{} HTTP/1.1\r\nHost: {API_HOST}\r\nAuthorization: Bearer {token}\r\nAccept: application/json\r\nUser-Agent: WhiteAesther\r\nConnection: close\r\nContent-Length: {}\r\n",
        request.method,
        request.path,
        body.len()
    );
    if request.body.is_some() {
        head.push_str(&format!("Content-Type: {}\r\n", request.content_type));
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes()).and_then(|_| stream.write_all(body)).map_err(|e| format!("Cloudflare could not be reached: {e}"))?;
    let mut raw = Vec::new();
    let mut buffer = [0u8; 8192];
    loop {
        match stream.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => {
                raw.extend_from_slice(&buffer[..count]);
                if raw.len() > MAX_RESPONSE + 65_536 {
                    return Err("Cloudflare response is too large".into());
                }
            }
            // A peer that closes without close_notify after a complete response.
            Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof && !raw.is_empty() => break,
            Err(error) => return Err(format!("Cloudflare did not answer: {error}").into()),
        }
    }
    let (status, text) = parse_response(&raw)?;
    if text.trim().is_empty() && (200..300).contains(&status) {
        return Ok(json!({ "success": true, "httpStatus": status }));
    }
    // A non-JSON answer (an edge error page) is quoted briefly so the failure can be diagnosed.
    let unreadable = || {
        let excerpt: String = text.split_whitespace().collect::<Vec<_>>().join(" ").chars().take(160).collect();
        ApiError { status, message: format!("Cloudflare returned HTTP {status}: {excerpt}") }
    };
    let mut value: Value = serde_json::from_str(&text).map_err(|_| unreadable())?;
    if !value.is_object() {
        return Err(unreadable());
    }
    if !(200..300).contains(&status) {
        value["success"] = json!(false);
    }
    value["httpStatus"] = json!(status);
    Ok(value)
}

/// Status and body of an HTTP/1.1 response, de-chunked.
pub(crate) fn parse_response(raw: &[u8]) -> Result<(u16, String), ApiError> {
    let split = raw.windows(4).position(|w| w == b"\r\n\r\n").ok_or("Cloudflare sent an incomplete response")?;
    let head = String::from_utf8_lossy(&raw[..split]);
    let mut body = raw[split + 4..].to_vec();
    let status: u16 = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok())
        .ok_or("Cloudflare sent an unreadable response")?;
    let chunked = head.lines().any(|line| {
        let lower = line.to_ascii_lowercase();
        lower.starts_with("transfer-encoding:") && lower.contains("chunked")
    });
    if chunked {
        let mut decoded = Vec::new();
        let mut rest = body.as_slice();
        loop {
            let end = rest.windows(2).position(|w| w == b"\r\n").ok_or("Cloudflare sent a truncated response")?;
            let size_text = String::from_utf8_lossy(&rest[..end]);
            let size = usize::from_str_radix(size_text.split(';').next().unwrap_or("").trim(), 16)
                .map_err(|_| "Cloudflare sent a malformed response")?;
            rest = &rest[end + 2..];
            if size == 0 {
                break;
            }
            if rest.len() < size {
                return Err("Cloudflare sent a truncated response".into());
            }
            decoded.extend_from_slice(&rest[..size]);
            rest = rest.get(size + 2..).unwrap_or_default();
        }
        body = decoded;
    }
    if body.len() > MAX_RESPONSE {
        return Err("Cloudflare response is too large".into());
    }
    Ok((status, String::from_utf8_lossy(&body).into_owned()))
}

fn now_secs() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs() as i64)
}

/// Proleptic Gregorian date from days since 1970-01-01 (Hinnant's algorithm).
fn civil(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (yoe + era * 400 + i64::from(month <= 2), month, day)
}

pub(crate) fn utc_date(secs: i64) -> String {
    let (y, m, d) = civil(secs.div_euclid(86_400));
    format!("{y:04}-{m:02}-{d:02}")
}

pub(crate) fn utc_instant(secs: i64) -> String {
    let rem = secs.rem_euclid(86_400);
    format!("{}T{:02}:{:02}:{:02}Z", utc_date(secs), rem / 3600, rem % 3600 / 60, rem % 60)
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

use tauri::{AppHandle, Manager};

fn carrier_socks(app: &AppHandle) -> Option<SocketAddr> {
    app.state::<crate::core_supervisor::CoreSupervisor>().connected_socks()?.parse().ok()
}

/// Runs `work` off the webview thread with an API built from `token`.
async fn with_api<T: Send + 'static>(
    app: AppHandle,
    token: String,
    work: impl FnOnce(&AppHandle, &WorkerApi) -> ApiResult<T> + Send + 'static,
) -> Result<T, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let api = WorkerApi::new(&token, carrier_socks(&app)).map_err(|e| e.message)?;
        work(&app, &api).map_err(|e| api.scrub(&e.message))
    })
    .await
    .map_err(|error| format!("the Cloudflare request did not finish: {error}"))?
}

fn saver(app: &AppHandle) -> impl Fn(&WorkerDeployment) -> Result<(), String> + '_ {
    move |row| crate::worker::write_deployment(app, &row.key(), Some(row))
}

fn stored(app: &AppHandle, key: &str) -> ApiResult<WorkerDeployment> {
    crate::worker::read_deployments(app)?
        .into_iter()
        .find(|row| row.key() == key)
        .ok_or_else(|| "This deployment is no longer saved on this computer".into())
}

/// Whether the Worker carrier is up or coming up on `key`.
fn in_use(app: &AppHandle, key: &str) -> bool {
    let snapshot = app.state::<crate::worker::Worker>().snapshot();
    matches!(snapshot.state.as_str(), "connecting" | "connected") && snapshot.deployment.as_deref() == Some(key)
}

/// A deployment as the screen sees it: everything except its identity.
fn public(row: &WorkerDeployment) -> Value {
    let mut value = serde_json::to_value(row).unwrap_or(Value::Null);
    if let Some(object) = value.as_object_mut() {
        object.remove("uuid");
        object.insert("key".into(), json!(row.key()));
    }
    value
}

#[tauri::command]
pub fn worker_status(worker: tauri::State<'_, crate::worker::Worker>) -> crate::worker::WorkerSnapshot {
    worker.snapshot()
}

#[tauri::command]
pub fn worker_token_url() -> String {
    token_template_url()
}

#[tauri::command]
pub fn worker_deployments(app: AppHandle) -> Result<Vec<Value>, String> {
    Ok(crate::worker::read_deployments(&app)?.iter().map(public).collect())
}

#[tauri::command]
pub async fn worker_accounts(app: AppHandle, token: String) -> Result<Vec<WorkerAccount>, String> {
    with_api(app, token, |_, api| api.accounts()).await
}

#[tauri::command]
pub async fn worker_create(app: AppHandle, token: String, account_id: String, pages: bool, relay: String) -> Result<Value, String> {
    with_api(app, token, move |app, api| {
        let deployment = WorkerDeployment::new(&account_id, pages, &relay)?;
        // Kept before the first remote write so a failed setup can be retried or deleted.
        saver(app)(&deployment)?;
        api.deploy(&deployment, &saver(app)).map(|row| public(&row))
    })
    .await
}

#[tauri::command]
pub async fn worker_update(app: AppHandle, token: String, key: String, relay: String) -> Result<Value, String> {
    with_api(app, token, move |app, api| {
        if in_use(app, &key) {
            return Err("Disconnect this Worker before changing its settings".into());
        }
        let deployment = WorkerDeployment { relay: relay.trim().to_string(), ..stored(app, &key)? };
        api.deploy(&deployment, &saver(app)).map(|row| public(&row))
    })
    .await
}

/// Saves connection settings; redeploys only when the script's settings change.
#[tauri::command]
pub async fn worker_save_options(
    app: AppHandle,
    token: String,
    key: String,
    options: crate::worker::WorkerOptions,
) -> Result<Value, String> {
    tauri::async_runtime::spawn_blocking(move || {
        options.validate()?;
        if in_use(&app, &key) {
            return Err("Disconnect this Worker before changing its settings".to_string());
        }
        let current = stored(&app, &key).map_err(|e| e.message)?;
        // The relay field folds into the proxy IPs, as on Android.
        let updated = WorkerDeployment { options, relay: String::new(), ..current.clone() };
        if updated.environment() == current.environment() {
            crate::worker::write_deployment(&app, &key, Some(&updated))?;
            return Ok(public(&updated));
        }
        if token.trim().is_empty() {
            return Err("Paste the API token to update proxy IPs or the fallback website on Cloudflare".into());
        }
        let api = WorkerApi::new(&token, carrier_socks(&app)).map_err(|e| e.message)?;
        api.deploy(&updated, &saver(&app)).map(|row| public(&row)).map_err(|e| api.scrub(&e.message))
    })
    .await
    .map_err(|error| format!("saving did not finish: {error}"))?
}

#[tauri::command]
pub async fn worker_attach_domain(app: AppHandle, token: String, key: String, hostname: String) -> Result<Value, String> {
    with_api(app, token, move |app, api| {
        if in_use(app, &key) {
            return Err("Disconnect before changing the deployment domain".into());
        }
        api.attach_domain(&stored(app, &key)?, &hostname, &saver(app)).map(|row| public(&row))
    })
    .await
}

#[tauri::command]
pub async fn worker_detach_domain(app: AppHandle, token: String, key: String) -> Result<Value, String> {
    with_api(app, token, move |app, api| {
        if in_use(app, &key) {
            return Err("Disconnect before changing the deployment domain".into());
        }
        api.detach_domain(&stored(app, &key)?, &saver(app)).map(|row| public(&row))
    })
    .await
}

#[tauri::command]
pub async fn worker_usage(app: AppHandle, token: String, key: String) -> Result<(u64, u64), String> {
    with_api(app, token, move |app, api| api.usage(&stored(app, &key)?)).await
}

#[tauri::command]
pub async fn worker_delete(app: AppHandle, token: String, key: String) -> Result<(), String> {
    with_api(app, token, move |app, api| {
        if in_use(app, &key) {
            return Err("Disconnect before deleting a deployment".into());
        }
        api.delete(&stored(app, &key)?)?;
        crate::worker::write_deployment(app, &key, None)?;
        Ok(())
    })
    .await
}

/// Removes a deployment record from this computer only; Cloudflare is not contacted.
#[tauri::command]
pub fn worker_forget(app: AppHandle, key: String) -> Result<(), String> {
    if in_use(&app, &key) {
        return Err("Disconnect before deleting a deployment".into());
    }
    crate::worker::write_deployment(&app, &key, None)
}

#[tauri::command]
pub async fn worker_account_list(app: AppHandle, token: String, account_id: String) -> Result<Vec<RemoteDeployment>, String> {
    with_api(app, token, move |_, api| api.list_account(&account_id)).await
}

#[tauri::command]
pub async fn worker_account_delete(app: AppHandle, token: String, account_id: String, name: String, pages: bool) -> Result<(), String> {
    with_api(app, token, move |app, api| {
        // A deployment saved here goes through its own path, which also detaches its domain.
        let kind = if pages { "pages" } else { "workers" };
        if crate::worker::read_deployments(app)?.iter().any(|row| row.key() == format!("{account_id}/{kind}/{name}")) {
            return Err("This deployment is listed above; delete it from its own card".into());
        }
        api.delete_named(&account_id, &name, pages)
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::worker::{WorkerMode, WorkerOptions};
    use std::sync::{Arc, Mutex};

    const TOKEN: &str = "abcdefghijklmnopqrstuvwxyz0123456789";
    const ACCOUNT: &str = "0123456789abcdef0123456789abcdef";

    type Log = Arc<Mutex<Vec<(String, String, String)>>>;

    /// A mock Cloudflare: each call is answered by the first matching route.
    fn api(routes: Vec<(&'static str, &'static str, Value)>) -> (WorkerApi, Log) {
        let log: Log = Arc::default();
        let seen = log.clone();
        let exchange: Exchange = Box::new(move |token, request| {
            assert_eq!(token, TOKEN);
            let body = request.body.as_ref().map(|b| String::from_utf8_lossy(b).into_owned()).unwrap_or_default();
            seen.lock().unwrap().push((request.method.clone(), request.path.clone(), body));
            for (method, prefix, response) in &routes {
                if request.method == *method && request.path.starts_with(prefix) {
                    return Ok(response.clone());
                }
            }
            Ok(json!({ "success": false, "httpStatus": 404, "errors": [{ "message": "not found", "code": 7003 }] }))
        });
        (WorkerApi::with_exchange(TOKEN, "export default {}", exchange).unwrap(), log)
    }

    fn ok(result: Value) -> Value {
        json!({ "success": true, "httpStatus": 200, "result": result })
    }

    fn fresh(pages: bool) -> WorkerDeployment {
        let mut d = WorkerDeployment::new(ACCOUNT, pages, "").unwrap();
        d.name = "whiteaesther-abc".into();
        d
    }

    #[test]
    fn tokens_must_be_the_token_itself() {
        let none: Exchange = Box::new(|_, _| unreachable!());
        assert!(WorkerApi::with_exchange("short", "", none).is_err());
        let none: Exchange = Box::new(|_, _| unreachable!());
        assert!(WorkerApi::with_exchange(&format!("\"{TOKEN}\""), "", none).is_err());
    }

    #[test]
    fn accounts_are_read_across_pages_and_checked() {
        let log: Log = Arc::default();
        let seen = log.clone();
        let exchange: Exchange = Box::new(move |_, request| {
            seen.lock().unwrap().push((request.method.clone(), request.path.clone(), String::new()));
            let page = if request.path.ends_with("page=1") { 1 } else { 2 };
            Ok(json!({ "success": true, "result": [{ "id": format!("{ACCOUNT}")[..31].to_string() + &page.to_string(), "name": format!("A{page}") }], "result_info": { "total_pages": 2 } }))
        });
        let api = WorkerApi::with_exchange(TOKEN, "", exchange).unwrap();
        let accounts = api.accounts().unwrap();
        assert_eq!(accounts.len(), 2);
        assert_eq!(accounts[1].name, "A2");
        assert_eq!(log.lock().unwrap().len(), 2);

        let (bad, _) = api_with_invalid_account();
        assert!(bad.accounts().unwrap_err().message.contains("invalid account"));
    }

    fn api_with_invalid_account() -> (WorkerApi, Log) {
        api(vec![("GET", "/accounts?", json!({ "success": true, "result": [{ "id": "nope", "name": "x" }] }))])
    }

    #[test]
    fn a_worker_deploys_with_its_env_and_enables_workers_dev() {
        let (api, log) = api(vec![
            ("GET", &"/accounts/0123456789abcdef0123456789abcdef/workers/subdomain"[..], ok(json!({ "subdomain": "me" }))),
            ("PUT", "/accounts/0123456789abcdef0123456789abcdef/workers/scripts/", ok(json!({}))),
            ("POST", "/accounts/0123456789abcdef0123456789abcdef/workers/scripts/", ok(json!({}))),
        ]);
        let saved = Mutex::new(Vec::new());
        let d = fresh(false);
        let deployed = api.deploy(&d, &|row| { saved.lock().unwrap().push(row.clone()); Ok(()) }).unwrap();
        assert!(deployed.ready && deployed.created);
        assert_eq!(deployed.host, "whiteaesther-abc.me.workers.dev");
        let calls = log.lock().unwrap();
        let upload = calls.iter().find(|c| c.0 == "PUT" && c.1.ends_with("/workers/scripts/whiteaesther-abc")).unwrap();
        assert!(upload.2.contains("filename=\"worker.js\""));
        assert!(upload.2.contains("application/javascript+module"));
        assert!(upload.2.contains(&d.environment()), "ENV binding carries the settings");
        assert!(upload.2.contains("\"main_module\":\"worker.js\""));
        let enable = calls.last().unwrap();
        assert!(enable.1.ends_with("/workers/scripts/whiteaesther-abc/subdomain"));
        assert!(enable.2.contains("\"previews_enabled\":false"));
        // The host is saved before the last remote write, then saved ready.
        let saved = saved.lock().unwrap();
        assert!(saved.iter().any(|row| !row.ready && row.created));
        assert!(saved.last().unwrap().ready);
    }

    #[test]
    fn a_missing_workers_subdomain_is_registered() {
        let (api, log) = api(vec![
            ("PUT", "/accounts/0123456789abcdef0123456789abcdef/workers/subdomain", ok(json!({ "subdomain": "new" }))),
            ("PUT", "/accounts/0123456789abcdef0123456789abcdef/workers/scripts/", ok(json!({}))),
            ("POST", "/accounts/", ok(json!({}))),
        ]);
        let deployed = api.deploy(&fresh(false), &|_| Ok(())).unwrap();
        assert_eq!(deployed.host, "whiteaesther-abc.new.workers.dev");
        assert!(log.lock().unwrap().iter().any(|c| c.0 == "PUT" && c.1.ends_with("/workers/subdomain") && c.2.contains("\"subdomain\"") && !c.2.contains("whiteaesther")));
    }

    #[test]
    fn pages_create_then_patch_and_upload_the_worker() {
        let (api, log) = api(vec![
            ("POST", "/accounts/0123456789abcdef0123456789abcdef/pages/projects/whiteaesther-abc/deployments", ok(json!({}))),
            ("POST", "/accounts/0123456789abcdef0123456789abcdef/pages/projects", ok(json!({ "subdomain": "whiteaesther-abc.pages.dev" }))),
            ("PATCH", "/accounts/0123456789abcdef0123456789abcdef/pages/projects/whiteaesther-abc", ok(json!({ "subdomain": "whiteaesther-abc.pages.dev" }))),
        ]);
        let deployed = api.deploy(&fresh(true), &|_| Ok(())).unwrap();
        assert_eq!(deployed.host, "whiteaesther-abc.pages.dev");
        let again = api.deploy(&deployed, &|_| Ok(())).unwrap();
        assert!(again.ready);
        let calls = log.lock().unwrap();
        assert!(calls[0].2.contains("\"production_branch\":\"main\""));
        assert!(calls[1].2.contains("filename=\"_worker.js\""));
        assert_eq!(calls[2].0, "PATCH");
        assert!(calls[2].2.contains("\"compatibility_date\""));
    }

    #[test]
    fn deleting_an_absent_deployment_succeeds() {
        let (api, log) = api(vec![]);
        api.delete(&fresh(false)).unwrap();
        assert_eq!(log.lock().unwrap()[0].1, "/accounts/0123456789abcdef0123456789abcdef/workers/scripts/whiteaesther-abc");
    }

    #[test]
    fn errors_are_reported_without_the_token() {
        let exchange: Exchange = Box::new(|token, _| Err(ApiError { status: 500, message: format!("bad {token}") }));
        let api = WorkerApi::with_exchange(TOKEN, "", exchange).unwrap();
        let error = api.accounts().unwrap_err();
        assert!(!error.message.contains(TOKEN));
        assert!(error.message.contains("[token]"));
    }

    #[test]
    fn a_worker_domain_tries_each_parent_zone() {
        let mut ready = fresh(false);
        ready.ready = true;
        ready.host = "whiteaesther-abc.me.workers.dev".into();
        let (api, log) = api(vec![
            ("GET", "/accounts/0123456789abcdef0123456789abcdef/workers/domains", ok(json!([]))),
            ("PUT", "/accounts/0123456789abcdef0123456789abcdef/workers/domains", json!({ "success": false, "httpStatus": 400, "errors": [{ "message": "zone", "code": 1 }] })),
        ]);
        let error = api.attach_domain(&ready, "vpn.example.com", &|_| Ok(())).unwrap_err();
        assert!(error.message.contains("must belong to this Cloudflare account"));
        let zones: Vec<String> = log.lock().unwrap().iter().filter(|c| c.0 == "PUT").map(|c| c.2.clone()).collect();
        assert_eq!(zones.len(), 2);
        assert!(zones[0].contains("\"zone_name\":\"vpn.example.com\""));
        assert!(zones[1].contains("\"zone_name\":\"example.com\""));
        assert!(api.attach_domain(&ready, "not a domain", &|_| Ok(())).is_err());
    }

    #[test]
    fn a_pages_domain_creates_a_proxied_cname_and_detach_removes_only_ours() {
        let mut ready = fresh(true);
        ready.ready = true;
        ready.host = "whiteaesther-abc.pages.dev".into();
        let zone = "fedcba9876543210fedcba9876543210";
        let record = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let (api, log) = api(vec![
            ("GET", "/zones?", ok(json!([{ "id": zone }]))),
            ("GET", "/zones/fedcba9876543210fedcba9876543210/dns_records?", ok(json!([]))),
            ("POST", "/zones/fedcba9876543210fedcba9876543210/dns_records", ok(json!({ "id": record }))),
            ("GET", "/accounts/0123456789abcdef0123456789abcdef/pages/projects/whiteaesther-abc/domains", ok(json!([]))),
            ("POST", "/accounts/0123456789abcdef0123456789abcdef/pages/projects/whiteaesther-abc/domains", ok(json!({}))),
            ("DELETE", "/accounts/", ok(json!({}))),
            ("GET", "/zones/fedcba9876543210fedcba9876543210/dns_records/", ok(json!({ "name": "vpn.example.com", "type": "CNAME", "content": "changed.example.com" }))),
        ]);
        let attached = api.attach_domain(&ready, "VPN.example.com", &|_| Ok(())).unwrap();
        assert_eq!(attached.custom_domain, "vpn.example.com");
        assert!(!attached.domain_pending);
        assert_eq!(attached.dns_record, record);
        assert!(log.lock().unwrap().iter().any(|c| c.0 == "POST" && c.2.contains("\"proxied\":true") && c.2.contains("\"type\":\"CNAME\"")));
        let detached = api.detach_domain(&attached, &|_| Ok(())).unwrap();
        assert!(detached.custom_domain.is_empty() && detached.dns_record.is_empty());
        // The record was changed by the operator, so it was not deleted.
        assert!(!log.lock().unwrap().iter().any(|c| c.0 == "DELETE" && c.1.starts_with("/zones/")));
    }

    #[test]
    fn usage_sums_both_counters() {
        let mut d = fresh(false);
        d.ready = true;
        let (api, log) = api(vec![("POST", "/graphql", json!({ "data": { "viewer": { "accounts": [{
            "total": [{ "sum": { "requests": 5 } }, { "sum": { "requests": 7 } }],
            "worker": [{ "sum": { "requests": 3 } }],
        }] } } }))]);
        assert_eq!(api.usage(&d).unwrap(), (12, 3));
        assert!(log.lock().unwrap()[0].2.contains("whiteaesther-abc"));
        assert!(api.usage(&fresh(true)).is_err());
    }

    #[test]
    fn options_survive_deploys() {
        let mut d = fresh(false);
        d.options = WorkerOptions { mode: WorkerMode::Browser, ..WorkerOptions::default() };
        let (api, _) = api(vec![("GET", "/accounts/", ok(json!({ "subdomain": "me" }))), ("PUT", "/accounts/", ok(json!({}))), ("POST", "/accounts/", ok(json!({})))]);
        assert_eq!(api.deploy(&d, &|_| Ok(())).unwrap().options.mode, WorkerMode::Browser);
    }

    #[test]
    fn the_token_template_prefills_every_permission() {
        let url = token_template_url();
        assert!(url.starts_with("https://dash.cloudflare.com/profile/api-tokens?permissionGroupKeys=%5B%7B%22key%22%3A%22account_settings%22"));
        assert!(url.ends_with("&accountId=*&zoneId=all&name=WhiteAesther"));
        for key in ["workers_scripts", "page", "zone", "dns", "account_analytics"] {
            assert!(url.contains(&format!("%22{key}%22")), "{key}");
        }
    }

    #[test]
    fn chunked_and_plain_responses_parse() {
        let plain = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}";
        assert_eq!(parse_response(plain).unwrap(), (200, "{}".into()));
        let chunked = b"HTTP/1.1 403 Forbidden\r\nTransfer-Encoding: chunked\r\n\r\n4\r\n{\"a\"\r\n4;x=y\r\n:1}\n\r\n0\r\n\r\n";
        assert_eq!(parse_response(chunked).unwrap(), (403, "{\"a\":1}\n".into()));
        assert!(parse_response(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nff\r\nab").is_err());
    }

    #[test]
    fn dates_are_utc_calendar_dates() {
        assert_eq!(utc_date(0), "1970-01-01");
        assert_eq!(utc_date(951_782_400), "2000-02-29");
        assert_eq!(utc_instant(1_793_923_199), "2026-11-05T23:59:59Z");
    }

    #[test]
    fn the_account_list_holds_workers_and_pages_and_names_are_checked() {
        let (api, log) = api(vec![
            ("GET", "/accounts/0123456789abcdef0123456789abcdef/workers/subdomain", ok(json!({ "subdomain": "me" }))),
            ("GET", "/accounts/0123456789abcdef0123456789abcdef/workers/scripts", ok(json!([{ "id": "old-proxy" }, { "id": "../bad" }]))),
            ("GET", "/accounts/0123456789abcdef0123456789abcdef/pages/projects", ok(json!([{ "name": "site", "subdomain": "site.pages.dev" }]))),
            ("DELETE", "/accounts/", ok(json!({}))),
        ]);
        let list = api.list_account(ACCOUNT).unwrap();
        assert_eq!(list, vec![
            RemoteDeployment { name: "old-proxy".into(), pages: false, host: "old-proxy.me.workers.dev".into() },
            RemoteDeployment { name: "site".into(), pages: true, host: "site.pages.dev".into() },
        ]);
        api.delete_named(ACCOUNT, "site", true).unwrap();
        assert_eq!(log.lock().unwrap().last().unwrap().1, "/accounts/0123456789abcdef0123456789abcdef/pages/projects/site");
        assert!(api.delete_named(ACCOUNT, "../x", false).is_err());
        assert!(api.list_account("nothex").is_err());
    }

    #[test]
    fn a_busy_edge_is_retried_and_then_reported() {
        let calls = Arc::new(Mutex::new(0));
        let seen = calls.clone();
        let exchange: Exchange = Box::new(move |_, _| {
            *seen.lock().unwrap() += 1;
            if *seen.lock().unwrap() < 3 {
                Err(ApiError { status: 503, message: "Cloudflare returned HTTP 503: busy".into() })
            } else {
                Ok(json!({ "success": true, "result": [] }))
            }
        });
        let api = WorkerApi::with_exchange(TOKEN, "", exchange).unwrap();
        assert!(api.accounts().unwrap().is_empty());
        assert_eq!(*calls.lock().unwrap(), 3);

        let always: Exchange = Box::new(|_, _| Ok(json!({ "success": false, "httpStatus": 503, "errors": [] })));
        let api = WorkerApi::with_exchange(TOKEN, "", always).unwrap();
        assert_eq!(api.accounts().unwrap_err().status, 503);
    }

    #[test]
    fn a_pages_project_left_by_a_lost_answer_is_patched() {
        let (api, log) = api(vec![
            ("POST", "/accounts/0123456789abcdef0123456789abcdef/pages/projects/whiteaesther-abc/deployments", ok(json!({}))),
            ("POST", "/accounts/0123456789abcdef0123456789abcdef/pages/projects", json!({ "success": false, "httpStatus": 409, "errors": [{ "message": "A project with this name already exists.", "code": 8000002 }] })),
            ("PATCH", "/accounts/0123456789abcdef0123456789abcdef/pages/projects/whiteaesther-abc", ok(json!({ "subdomain": "whiteaesther-abc.pages.dev" }))),
        ]);
        assert!(api.deploy(&fresh(true), &|_| Ok(())).unwrap().ready);
        assert_eq!(log.lock().unwrap()[1].0, "PATCH");
    }

    /// Live: a JSON POST with a dummy token must come back as Cloudflare's JSON 401.
    #[test]
    #[ignore]
    fn live_post_reaches_cloudflare() {
        let body = json!({ "name": "whiteaesther-x", "production_branch": "main" });
        let request = ApiRequest::new("POST", &format!("/accounts/{ACCOUNT}/pages/projects"), Some(body));
        let answer = request_https(None, "abcdefghijklmnopqrstuvwxyz0123456789ABCD", &request);
        println!("{answer:?}");
        assert_eq!(answer.unwrap()["httpStatus"], 401);
    }

    #[test]
    fn unexpected_paths_never_leave_the_machine() {
        let request = ApiRequest::new("GET", "/user/tokens", None);
        assert!(request_https(None, TOKEN, &request).unwrap_err().message.contains("unexpected"));
        let request = ApiRequest::new("GET", "/accounts/../user", None);
        assert!(request_https(None, TOKEN, &request).is_err());
    }
}
