// Synthetic bridge retirement exercises the original protocol and encrypted store.
fn completed_call(binding:&Value)->Value {
    json!({"call_id":binding["call_id"],"sequence":binding["sequence"],"frame_digest":binding["frame_digest"],"state":"RESULT_UNKNOWN","outcome_digest":"0".repeat(64),"report_version":2,"retirement":"SERVICE_CONFIRMED_CONSUMED"})
}
#[test]
fn sparse_completed_calls_are_fenced_after_restart_without_retiring_the_old_hole() {
    let root=crate::test_support::protected_test_dir();let path=root.path().join("bridge");create_private_state_directory(&path).unwrap();
    let destination=json!({"host":"CODEX_APP_SERVER","conversation_id":"thread","session_id":"session"});
    let mut store=store::Store::open(&path,"sparse",true).unwrap();
    let (first,one)=frame(&destination,1);let (second,two)=frame(&destination,2);
    for (binding,message) in [(&first,&one),(&second,&two)] {
        store.reserve(binding,message["message_id"].as_str().unwrap(),binding["frame_digest"].as_str().unwrap(),Some(message)).unwrap();
        store.finish(binding,&json!({"state":"RESULT_UNKNOWN","code":"HOST_ACK_UNKNOWN"})).unwrap();
    }
    let scope=access_scope(&second);let selected=completed_call(&second);
    assert_eq!(store.retire(&scope,0,&[selected.clone()]).unwrap(),1);
    drop(store);let mut store=store::Store::open(&path,"sparse",false).unwrap();
    assert_eq!(store.retire(&scope,0,&[selected]).unwrap(),0);
    assert!(!store.retired(&first).unwrap());assert!(store.retired(&second).unwrap());
    assert_eq!(store.get(&first,one["message_id"].as_str().unwrap(),first["frame_digest"].as_str().unwrap()).unwrap().unwrap()["state"],"RESULT_UNKNOWN");
    assert_eq!(store.reserve(&second,two["message_id"].as_str().unwrap(),second["frame_digest"].as_str().unwrap(),Some(&two)).unwrap_err(),"HOST_EVIDENCE_RETIRED");
    store.finish(&second,&json!({"state":"HOST_ACCEPTED","receipt":"late"})).unwrap();
    assert!(store.get(&second,two["message_id"].as_str().unwrap(),second["frame_digest"].as_str().unwrap()).unwrap().is_none());
    let sql=rusqlite::Connection::open(path.join("bridge.sqlite")).unwrap();
    assert_eq!(sql.query_row("SELECT count(*) FROM bridge_calls WHERE frame IS NOT NULL",[],|r|r.get::<_,u64>(0)).unwrap(),0,"only Runtime retains rendered private input");
}
#[test]
fn retirement_refuses_a_live_physical_input_and_authenticates_sparse_fences() {
    let root=crate::test_support::protected_test_dir();let path=root.path().join("bridge");create_private_state_directory(&path).unwrap();
    let destination=json!({"host":"CODEX_APP_SERVER","conversation_id":"thread","session_id":"session"});
    let mut store=store::Store::open(&path,"active",true).unwrap();let (binding,message)=frame(&destination,2);let scope=access_scope(&binding);let selected=completed_call(&binding);
    store.reserve(&binding,message["message_id"].as_str().unwrap(),binding["frame_digest"].as_str().unwrap(),Some(&message)).unwrap();
    assert_eq!(store.retire(&scope,0,&[selected.clone()]).unwrap_err(),"HOST_RETIREMENT_ACTIVE_INPUT");
    store.finish(&binding,&json!({"state":"RESULT_UNKNOWN","code":"HOST_ACK_UNKNOWN"})).unwrap();store.retire(&scope,0,&[selected]).unwrap();
    let sql=rusqlite::Connection::open(path.join("bridge.sqlite")).unwrap();sql.execute("UPDATE bridge_closed_ranges SET hi=hi+1",[]).unwrap();
    assert_eq!(store.retired(&binding).unwrap_err(),"BRIDGE_STATE_INVALID");
}
