use time::OffsetDateTime;

fn main() {
    // let now = OffsetDateTime::now_local();
    println!("Hello, World. The current time is {}", OffsetDateTime::now_utc());
}
