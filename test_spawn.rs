use std::process::Command;
use std::os::unix::process::CommandExt;
fn main() {
    let mut cmd = Command::new("false");
    unsafe {
        cmd.pre_exec(|| {
            libc::_exit(127);
        });
    }
    match cmd.spawn() {
        Ok(child) => println!("Ok(Child)"),
        Err(e) => println!("Err({:?})", e),
    }
}
