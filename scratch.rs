use std::io;

fn main() {
    let err = io::Error::last_os_error();
    println!("{:?}", err);
}
