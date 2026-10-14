//! Live runtime schema probe: the real Stop logic with an isolated Appendix C fake helper.
//! No installed helper paths or credentials are accessible through this example.

#[cfg(unix)]
fn main() -> std::io::Result<()> {
    use serde_json::{json, Value};
    use std::io::{BufRead, Read, Write};
    let args: Vec<String> = std::env::args().collect();
    let input: Value = serde_json::from_reader(std::io::stdin())?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let ppid = std::os::unix::process::parent_id();
    let mut stream = std::io::BufReader::new(std::os::unix::net::UnixStream::connect(&args[2])?);
    stream
        .get_mut()
        .set_read_timeout(Some(std::time::Duration::from_secs(2)))?;
    stream
        .get_mut()
        .set_write_timeout(Some(std::time::Duration::from_secs(2)))?;
    let output = kv_hook::stop::handle_stop(&args[1], &input, ppid, now, |op, params| {
        writeln!(
            stream.get_mut(),
            "{}",
            json!({"id": 1,"op":op,"params":params})
        )?;
        let mut line = String::new();
        (&mut stream).take(64 * 1024).read_line(&mut line)?;
        let reply: Value = serde_json::from_str(&line)?;
        if !line.ends_with('\n') || reply["ok"] != true {
            return Err(std::io::Error::other("Invalid fixture response"));
        }
        Ok(reply["result"].clone())
    });
    let record = json!({"fields": input.as_object().map(|o| o.keys().collect::<Vec<_>>()), "ppid":ppid,
        "stop_hook_active":input["stop_hook_active"], "loop_count":input["loop_count"], "output":output.value});
    writeln!(
        std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(&args[3])?,
        "{record}"
    )?;
    println!("{}", output.value);
    Ok(())
}

#[cfg(not(unix))]
fn main() {
    eprintln!("This isolated Unix-socket runtime probe requires Unix.");
}
