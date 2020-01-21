use std::env;
use std::collections::HashMap;
use std::time::Duration;

use futures_util::stream::TryStreamExt;

use tokio::time::delay_for;

use trust_dns_resolver::TokioAsyncResolver;
use trust_dns_resolver::config::*;

use hyper::{client::{Client, connect::Connect}, Request, Body};

use once_cell::sync::Lazy;

use regex::Regex;

use percent_encoding::{utf8_percent_encode, AsciiSet, CONTROLS};

use htmlescape::decode_html;

use log::error;

const FRAGMENT: &AsciiSet = &CONTROLS.add(b';').add(b':').add(b'/').add(b',');

static COOKIE: Lazy<Regex> = Lazy::new(|| Regex::new(r#"([^=]+)=([^;]+)"#).unwrap());
static INPUT_FIELDS: Lazy<Regex> = Lazy::new(|| Regex::new(r#"(<input[^>]+type="([^"]+)"[^>]+name="([^"]+)"([^>]+value="([^"]+)")?([^>]+checked)?|<textarea[^>]+name="([^"]+)"( required)?>([\s\S]*?)</textarea>)"#).unwrap());

async fn call<C>(client: &Client<C>, method: &str, url: &str, headers: Option<HashMap<&str, String>>, body: Option<String>, mut cookies_jar: Option<&mut HashMap<String, String>>) -> Result<String, ()>
where C: Connect + Clone + Send + Sync + 'static,
{
    let mut method = method;
    let mut url = url.to_string();
    let mut body = body;
    loop {
        let mut builder = Request::builder()
            .method(method)
            .uri(&url);
        if let Some(ref jar) = cookies_jar {
            builder = builder.header("Cookie", jar.iter().map(|(key, value)| format!("{}={}", key, value)).collect::<Vec<String>>().join("; "));
        }
        if let Some(ref h) = headers {
            for (name, value) in h {
                builder = builder.header(*name, value);
            }
        }
        let req = builder.body(if let Some(b) = body { Body::from(b) } else { Body::empty() }).map_err(|e| error!("error building request to {}: {}", url, e))?;

        let res = client.request(req).await.map_err(|e| error!("error receiving response from {}: {}", url, e))?;
        let success = res.status().is_success();
        let redirect = res.status().is_redirection();
        let (head, stream) = res.into_parts();
        let chunks = stream.map_ok(|c| c.to_vec()).try_concat().await.map_err(|e| error!("error while reading response from {}: {}", url, e))?;
        let res_body = String::from_utf8(chunks.to_vec()).map_err(|e| error!("error while encoding response from {}: {}", url, e))?;
        if success || redirect {
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
    let ddnss: Vec<&str> = ddnss.split(";").collect();

    let client = Client::new();
    let mut cookies_jar = HashMap::new();
    call(&client, "GET", &format!("{}login", url), None, None, Some(&mut cookies_jar)).await?;
    call(&client, "POST", &format!("{}login", url), Some({
            let mut headers = HashMap::new();
            headers.insert("Referer", format!("{}login", url));
            headers
        }), Some(format!("username-email={}&password={}&_csrf={}",
            utf8_percent_encode(&username, FRAGMENT),
            utf8_percent_encode(&password, FRAGMENT),
            utf8_percent_encode(&cookies_jar["CSRF-TOKEN"], FRAGMENT)
        )), Some(&mut cookies_jar)).await?;

    let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default()).await.map_err(|e| error!("Failed to init Resolver: {}", e))?;

    loop {
        let body = call(&client, "GET", &format!("{}dashboard/settings", url), None, None, Some(&mut cookies_jar)).await?;
        let mut fields = HashMap::new();
        for m in INPUT_FIELDS.captures_iter(&body){
            /*
             * 0 => full match
             * 1 => OR match
             * 2 => input type
             * 3 => input name
             * 4 => input value match
             * 5 => input value
             * 6 => input checked
             * 7 => textarea name
             * 8 => textarea required
             * 9 => textarea value
             */
            if let Some(key) = m.get(3).or_else(|| m.get(7)) {
                if !((m.get(2).map(|m| m.as_str()) == Some("checkbox") || m.get(2).map(|m| m.as_str()) == Some("radio")) && m.get(6).map(|m| m.as_str()) != Some(" checked")) {
                    fields.insert(key.as_str(), decode_html(m.get(5).or_else(|| m.get(9)).map(|s| s.as_str()).unwrap_or_else(|| "")).map_err(|e| error!("Value decode error: {:?}", e))?);
                }
            }
        }

        let mut addresses = Vec::new();
        for ddns in &ddnss {
            if let Ok(response) = resolver.lookup_ip(*ddns).await.map_err(|e| error!("Failed to lookup \"{}\": {}", ddns, e)) {
                for address in response.iter() {
                    addresses.push(format!("{}", address));
                }
            }
        }
        let addresses = addresses.join(";");
        if fields["deviceapi_host_whitelist"] != addresses {
            fields.insert("deviceapi_host_whitelist", addresses);

            call(&client, "POST", &format!("{}dashboard/settings", url), Some({
                    let mut headers = HashMap::new();
                    headers.insert("Referer", format!("{}dashboard/settings", url));
                    headers.insert("Content-Type", String::from("application/x-www-form-urlencoded"));
                    headers
                }), Some(fields.into_iter().map(|(k, v)| format!("{}={}", k, utf8_percent_encode(&v, FRAGMENT))).collect::<Vec<String>>().join("&")), Some(&mut cookies_jar)).await?;
        }

        delay_for(Duration::from_secs(60)).await;
    }
}
