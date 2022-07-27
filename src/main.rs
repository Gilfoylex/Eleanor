use std::io;
use env_logger::Env;

mod tunproxy;
mod outbound_connectors;
mod error;

#[tokio::main]
async fn main() -> io::Result<()> {
    let env = Env::default()
        .filter_or("MY_LOG_LEVEL", "trace")
        .write_style_or("MY_LOG_STYLE", "always");

    env_logger::init_from_env(env);
    
    let mut builder = tunproxy::TunBuilder::new();
    builder = builder.address("10.0.0.0/24".parse().unwrap()).name("tun0");
    let server = builder.build()?;
    _ = server.run().await;

    Ok(())
}