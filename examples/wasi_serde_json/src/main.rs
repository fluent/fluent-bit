// Import rust's io and filesystem module
use std::io::prelude::*;
use std::fs;
// Import pure and fast JSON library written in Rust
use serde_json::json;
// Import chrono library to handle time related operation conveniently
use chrono::Utc;

// Entry point to our WASI applications
fn main() {
  // Note that fractional second must be handled by `.%9f` not `%L` like as fluent-bit.
  let time = Utc::now().format("%Y-%m-%dT%H:%M:%S.%9f %z").to_string();
  // The type of `john` is `serde_json::Value`
  let john = json!({
      "name": "John Doe",
      "age": 43,
      "phones": [
          "+44 1234567",
          "+44 2345678"
      ],
      "time": format!("{}", time),
  });
  // Print out serialized JSON data for john
  // This will handle writing to stdout for us using the WASI APIs (e.g fd_write)
  println!("{}", john.to_string());

  // Create a file (Testing for exposed wasi API)
  let mut file = fs::File::create("helloworld.txt").expect("Unable to create file");

  // Write the text to the file we created (Testing for exposed wasi API)
  write!(file, "Hello world!\n").unwrap();
}