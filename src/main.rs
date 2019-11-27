use std::env;

use trust_dns_resolver::AsyncResolver;
use trust_dns_resolver::config::*;

use mysql_async::Conn;
use mysql_async::prelude::Queryable;

use log::error;

#[tokio::main]
async fn main() -> Result<(), ()> {
    let conn = Conn::new(&env::var("DATABASE_URL").map_err(|_| error!("Missing env var DATABASE_URL"))?)
        .await.map_err(|e| error!("Can't connect to MySQL: {}", e))?;

    let res = conn.query("SELECT value FROM metadata WHERE `key` = 'DEVICEAPI_HOST_WHITELIST'")
        .await.map_err(|e| error!("Can't query MySQL: {}", e))?;

    let (_, ips) = res.reduce_and_drop(Vec::new(), |mut v, mut row| {
            let value: String = row.take("value").expect("MySQL metadata.value decode error");
            v.extend(value.split(";").map(|s| s.to_owned()));
            v
        }).await.map_err(|e| error!("Can't retrive MySQL results: {}", e))?;

    let (resolver, background) = AsyncResolver::new(ResolverConfig::default(), ResolverOpts::default());
    tokio::spawn(background);

    let ddns = "cosmico89nas1.myqnapcloud.com";
    let response = resolver.lookup_ip(ddns).await.map_err(|e| error!("Failed to lookup \"{}\": {}", ddns, e))?;

    for address in response.iter() {
        let s = format!("{}", address);
        if !ips.contains(&s) {
            println!("DEVICEAPI_HOST_WHITELIST doesn't contains {}", s);
        }
    }

    Ok(())
}
