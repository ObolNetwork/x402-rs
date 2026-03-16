use std::process;

use x402_facilitator_prometheus_overlay::run;

#[tokio::main]
async fn main() {
    let result = run().await;
    if let Err(error) = result {
        println!("{error}");
        process::exit(1);
    }
}
