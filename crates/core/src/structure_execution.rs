//! Transport/assurance identifiers only. Business evaluation belongs to the
//! backend; these identifiers never enable local workspace replay.

pub const PROFILE: &str = "backend-structure-v1";

/// Historical Owner checkpoint evidence is authenticated on reads, but is
/// never a supported online mutation or a locally resumable transport intent.
pub fn is_owner_checkpoint_evidence(action:&str)->bool {
    matches!(action,"structure.checkpoint.begin"|"structure.checkpoint.instance"|"structure.checkpoint.records"|"structure.checkpoint.relations")
}

#[derive(Debug,Clone,Copy,PartialEq,Eq)]
pub enum StructureOperationKind { Mutation, Read, Control }

pub const STRUCTURE_MUTATIONS: &[&str] = &[
    "structure.access.authorize",
    "structure.access.end",
    "structure.action",
    "structure.adopt",
    "structure.communication.grant.set",
    "structure.communication.subscription.set",
    "structure.content-key.deliver",
    "structure.content-key.history.deliver",
    "structure.content-key.set",
    "structure.delivery.route.claim",
    "structure.delivery.route.close",
    "structure.grant.revoke",
    "structure.grant.set",
    "structure.mailbox.claim",
    "structure.mailbox.close",
    "structure.mailbox.create",
    "structure.maintenance.cancel",
    "structure.maintenance.rebuild",
    "structure.member.set",
    "structure.message.send",
    "structure.message.withdraw",
    "structure.migration.commit",
    "structure.migration.open",
    "structure.migration.source.ack",
    "structure.migration.source.request",
    "structure.protocol.bind",
    "structure.protocol.register",
    "structure.publication.entry.set",
    "structure.publication.entry.withdraw",
    "structure.publication.policy.set",
    "structure.publication.set",
    "structure.record.withdraw",
    "structure.workspace.create",
    "structure.workspace.delete",
];

pub const STRUCTURE_READS: &[&str] = &[
    "structure.access.approval.get",
    "structure.communication.grant.get",
    "structure.communication.stream.get",
    "structure.communication.subscriptions.read",
    "structure.content-key.delivery.get",
    "structure.content-key.get",
    "structure.content-key.history.get",
    "structure.content-key.history.jobs.read",
    "structure.content-keys.read",
    "structure.delivery.inbox.read",
    "structure.delivery.receipt.get",
    "structure.delivery.route.get",
    "structure.delivery.routes.read",
    "structure.delivery.stream.get",
    "structure.events.read",
    "structure.grant.get",
    "structure.instance.get",
    "structure.instance.resolve",
    "structure.instances.read",
    "structure.mailbox.get",
    "structure.mailbox.inbox.read",
    "structure.mailboxes.read",
    "structure.maintenance.get",
    "structure.members.read",
    "structure.message.get",
    "structure.message.receipts.read",
    "structure.migration.get",
    "structure.migration.info",
    "structure.migration.source.get",
    "structure.migration.source.read",
    "structure.migration.upload.get",
    "structure.operation.get",
    "structure.operations.read",
    "structure.protocol.resolve",
    "structure.protocol.resource.get",
    "structure.publication.policy.get",
    "structure.publication.prepare.get",
    "structure.record.get",
    "structure.records.read",
    "structure.workspace.deletion.get",
    "structure.workspace.deletions.read",
    "structure.workspace.get",
];

pub const STRUCTURE_CONTROLS: &[&str] = &[
    "structure.delivery.ack",
    "structure.delivery.pulse",
    "structure.mailbox.ack",
    "structure.mailbox.report",
    "structure.mailbox.pulse",
];

pub fn operation_kind(action:&str)->Option<StructureOperationKind>{
    if STRUCTURE_MUTATIONS.contains(&action){Some(StructureOperationKind::Mutation)}
    else if STRUCTURE_READS.contains(&action){Some(StructureOperationKind::Read)}
    else if STRUCTURE_CONTROLS.contains(&action){Some(StructureOperationKind::Control)}else{None}
}
pub fn is_structure_mutation(action:&str)->bool{operation_kind(action)==Some(StructureOperationKind::Mutation)}
pub fn is_structure_action(action:&str)->bool{operation_kind(action).is_some()}

/// These operations bind the selected instance in the authenticated command,
/// or in an explicit instance selector. Workspace-wide reads/administration
/// cannot acquire an instance boundary merely by adding header fields.
pub fn is_instance_scoped(action:&str)->bool{
    matches!(action,"structure.action"|"structure.instance.get"|"structure.instance.resolve"|
        "structure.protocol.resolve"|"structure.protocol.resource.get"|
        "structure.record.get"|"structure.record.withdraw"|"structure.records.read"|
        "structure.publication.prepare.get"|"structure.grant.get"|"structure.grant.set"|"structure.grant.revoke"|
        "structure.maintenance.get"|"structure.maintenance.rebuild"|"structure.maintenance.cancel"|
        "structure.events.read")||action.starts_with("structure.delivery.")&&is_structure_action(action)
}
pub fn has_body_instance_selector(action:&str)->bool{
    matches!(action,"structure.instance.resolve"|"structure.protocol.resolve"|"structure.protocol.resource.get")
}

#[cfg(test)]
mod delivery_contract_tests {
    use super::*;
    #[test]
    fn delivery_control_has_a_finite_surface_and_no_heartbeat_mutation_log() {
        for action in ["structure.delivery.route.claim", "structure.delivery.route.close", "structure.delivery.route.get", "structure.delivery.routes.read", "structure.delivery.inbox.read", "structure.delivery.receipt.get", "structure.delivery.stream.get", "structure.delivery.pulse", "structure.delivery.ack"] {
            assert!(is_structure_action(action));
        }
        assert!(!is_structure_mutation("structure.delivery.pulse"));
        assert!(!is_structure_mutation("structure.delivery.ack"));
        assert!(is_structure_mutation("structure.delivery.route.claim"));
        assert!(!is_structure_action("structure.delivery.arbitrary"));
    }
}

/// Native mail is workspace-scoped; SOURCE references and stream scopes carry
/// additional explicit selectors that local capabilities must inspect.
pub fn is_communication_action(action:&str)->bool{
    (action.starts_with("structure.communication.")||action.starts_with("structure.mailbox.")
    ||action=="structure.mailboxes.read"||action.starts_with("structure.message."))&&is_structure_action(action)
}
