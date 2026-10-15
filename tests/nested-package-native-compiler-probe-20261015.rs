// Pure diagnostic linked to an existing immutable cohort core rlib; no service.
fn main() {
    let path=std::env::args().nth(1).expect("closure path");
    let bytes=std::fs::read(path).expect("read closure");
    match peerwork_core::public_direct_install::compile_public_package_closure_with_bindings(&bytes,b"{}") {
        Ok(value)=>println!("OK {}",value.protocol_digest()),
        Err(error)=>{println!("ERR {:?}",error);std::process::exit(2);}
    }
}
