use std::env;
use std::collections::HashMap;
use std::time::Duration;

use futures_util::try_stream::TryStreamExt;

use tokio::timer::delay_for;

use trust_dns_resolver::AsyncResolver;
use trust_dns_resolver::config::*;

use hyper::{client::{Client, connect::Connect}, Request, Body};

use once_cell::sync::Lazy;

use regex::Regex;

use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};

use log::error;

static COOKIE: Lazy<Regex> = Lazy::new(|| Regex::new(r#"([^=]+)=([^;]+)"#).unwrap());
static INPUT_FIELDS: Lazy<Regex> = Lazy::new(|| Regex::new(r#"(<input[^>]+type="([^"]+)"[^>]+name="([^"]+)"([^>]+value="([^"]+)")?([^>]+checked)?|<textarea[^>]+name="([^"]+)">(.*)</textarea>)"#).unwrap());

async fn call<C>(client: &Client<C>, method: &str, url: &str, headers: Option<HashMap<&str, String>>, body: Option<String>, mut cookies_jar: Option<&mut HashMap<String, String>>) -> Result<String, ()>
where C: Connect + 'static,
{
    let mut method = method;
    let mut url = url.to_string();
    let mut body = body;
    loop {
        println!("url {}", url);
        let mut builder = Request::builder();
        builder.method(method).uri(&url);
        if let Some(ref jar) = cookies_jar {
            builder.header("Cookie", jar.iter().map(|(key, value)| format!("{}={}", key, value)).collect::<Vec<String>>().join("; "));
        }
        if let Some(ref h) = headers {
            for (name, value) in h {
                builder.header(*name, value);
            }
        }
        let req = builder.body(if let Some(b) = body { Body::from(b) } else { Body::empty() }).map_err(|e| error!("error building request to {}: {}", url, e))?;

        let res = client.request(req).await.map_err(|e| error!("error receiving response from {}: {}", url, e))?;
        let success = res.status().is_success();
        let redirect = res.status().is_redirection();
        let (head, stream) = res.into_parts();
        let chunks = stream.try_concat().await.map_err(|e| error!("error while reading response from {}: {}", url, e))?;
        let res_body = String::from_utf8(chunks.to_vec()).map_err(|e| error!("error while encoding response from {}: {}", url, e))?;
        if success || redirect {
            println!("Head {:?}", head);
            if let Some(ref mut jar) = cookies_jar {
                head.headers.get_all("Set-Cookie").into_iter().for_each(|c| {
                    if let Ok(s) = c.to_str() {
                        if let Some(captures) = COOKIE.captures(s) {
                            match (captures.get(1), captures.get(2)) {
                                (Some(key), Some(value)) => {
                                    jar.insert(key.as_str().to_string(), value.as_str().to_string());
                                },
                                _ => {},
                            }
                        }
                    }
                });
            }

            if success {
                return Ok(res_body);
            }
            else {
                if let Some(location) = head.headers.get("Location") {
                    method = "GET";
                    let location = location.to_str().map_err(|e| error!("Location header decode error: {}", e))?;
                    if location.starts_with("http") {
                        url = location.to_string();
                    }
                    else {
                        url = format!("{}{}", url.split("/").take(3).collect::<Vec<&str>>().join("/"), location);
                    }
                    body = None;
                }
                else {
                    error!("Locationless redirect");
                    return Err(());
                }
            }
        }
        else {
            error!("unsucessfull response from {}: {:?}\nbody: {}", url, head, res_body);
            return Err(());
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), ()> {
    env_logger::init();

    let url = env::var("RDM_URL").map_err(|_| error!("Missing env var RDM_URL"))?;
    let username = env::var("RDM_USERNAME").map_err(|_| error!("Missing env var RDM_USERNAME"))?;
    let password = env::var("RDM_PASSWORD").map_err(|_| error!("Missing env var RDM_PASSWORD"))?;
    let ddnss = env::var("DDNS").map_err(|_| error!("Missing env var DDNS"))?;

    let client = Client::new();
    let mut cookies_jar = HashMap::new();
    call(&client, "GET", &format!("{}login", url), None, None, Some(&mut cookies_jar)).await?;
    call(&client, "POST", &format!("{}login", url), Some({
            let mut headers = HashMap::new();
            headers.insert("Referer", format!("{}login", url));
            headers
        }), Some(format!("username-email={}&password={}&_csrf={}",
            utf8_percent_encode(&username, NON_ALPHANUMERIC),
            utf8_percent_encode(&password, NON_ALPHANUMERIC),
            utf8_percent_encode(&cookies_jar["CSRF-TOKEN"], NON_ALPHANUMERIC)
        )), Some(&mut cookies_jar)).await?;

    let (resolver, background) = AsyncResolver::new(ResolverConfig::default(), ResolverOpts::default());
    tokio::spawn(background);

    loop {
        let body = call(&client, "GET", &format!("{}dashboard/settings", url), None, None, Some(&mut cookies_jar)).await?;
        let mut fields = HashMap::new();
        INPUT_FIELDS.captures_iter(&body).for_each(|m| if let Some(key) = m.get(3).or_else(|| m.get(7)) {
            if (m.get(2).map(|m| m.as_str()) == Some("checkbox") || m.get(2).map(|m| m.as_str()) == Some("radio")) && m.get(6).map(|m| m.as_str()) != Some(" checked") {
                return;
            }
            fields.insert(key.as_str(), m.get(5).or_else(|| m.get(8)).map(|s| s.as_str()).unwrap_or_else(|| "").to_string());
        });

        let mut addresses = Vec::new();
        for ddns in ddnss.split(";") {
            let response = resolver.lookup_ip(ddns).await.map_err(|e| error!("Failed to lookup \"{}\": {}", ddns, e))?;

            for address in response.iter() {
                addresses.push(format!("{}", address));
            }
        }
        fields.insert("deviceapi_host_whitelist", addresses.join(";"));

        call(&client, "POST", &format!("{}dashboard/settings", url), Some({
                let mut headers = HashMap::new();
                headers.insert("Referer", format!("{}dashboard/settings", url));
                headers
            }), Some(fields.into_iter().map(|(k, v)| format!("{}={}", k, utf8_percent_encode(&v, NON_ALPHANUMERIC))).collect::<Vec<String>>().join("&")), Some(&mut cookies_jar)).await?;

        delay_for(Duration::from_secs(60)).await;
    }
}
