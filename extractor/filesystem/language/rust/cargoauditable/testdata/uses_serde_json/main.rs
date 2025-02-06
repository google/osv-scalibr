// Source Code used to create the uses_json binary.

/* Cargo.toml

[package]
name = "uses_json"
version = "0.1.0"
edition = "2021"

[dependencies]
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
*/

use serde::{Deserialize, Serialize};
use serde_json::Result;

#[derive(Serialize, Deserialize)]
struct Thingy {
    name: String,
    id: u32,
}

fn deserialize(data: &str) -> Result<Thingy> {
    Ok(serde_json::from_str(data)?)
}

fn serialize(p: &Thingy) -> Result<String> {
    let j = serde_json::to_string(&p)?;
    Ok(j)
}

fn main() -> Result<()> {
    let data = r#"{"name": "foo", "id": 314}"#;
    let obj = deserialize(&data)?;

    println!("Thingy '{}' has id {}", obj.name, obj.id);

    println!("{}", serialize(&obj)?);
    Ok(())
}
