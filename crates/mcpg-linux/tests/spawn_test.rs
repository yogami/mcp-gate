use std::process::Command;
use std::os::unix::process::CommandExt;
#[test]
fn test_spawn() {
    let mut cmd = Command::new("false");
    unsafe {
        cmd.pre_exec(|| {
            libc::_exit(127);
        });
    }
    match cmd.spawn() {
        Ok(_) => println!("SPAWN RETURNED OK!"),
        Err(_) => println!("SPAWN RETURNED ERR!"),
    }
}
