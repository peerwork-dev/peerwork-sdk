//! Transport/assurance identifiers only. Business evaluation belongs to the
//! backend; these identifiers never enable local workspace replay.

pub const PROFILE: &str = "backend-structure-v1";

/// Historical Owner checkpoint evidence is authenticated on reads, but is
/// never a supported online mutation or a locally resumable transport intent.
pub fn is_owner_checkpoint_evidence(action:&str)->bool {
    matches!(action,"structure.checkpoint.begin"|"structure.checkpoint.instance"|"structure.checkpoint.records"|"structure.checkpoint.relations")
}

pub fn is_structure_mutation(action: &str) -> bool {
    matches!(action, "structure.migration.open" | "structure.migration.commit" | "structure.migration.source.request" | "structure.migration.source.ack" | "structure.workspace.delete" | "structure.record.withdraw" | "structure.publication.policy.set" | "structure.publication.entry.withdraw" | "structure.content-key.history.deliver" | "structure.publication.set" | "structure.publication.entry.set" | "structure.access.end" | "structure.workspace.create" | "structure.adopt" | "structure.action"
        | "structure.member.set" | "structure.grant.set" | "structure.grant.revoke"
        | "structure.maintenance.rebuild" | "structure.maintenance.cancel" | "structure.access.authorize" | "structure.content-key.set" | "structure.content-key.deliver")
}

pub fn is_structure_action(action: &str) -> bool {
    matches!(action,
        "structure.migration.info" | "structure.migration.open" | "structure.migration.get" | "structure.migration.upload.get" | "structure.migration.commit" | "structure.migration.source.request" | "structure.migration.source.get" | "structure.migration.source.read" | "structure.migration.source.ack" | "structure.workspace.delete" | "structure.workspace.deletion.get" | "structure.workspace.deletions.read" | "structure.record.withdraw" | "structure.publication.policy.get" | "structure.publication.policy.set" | "structure.publication.entry.withdraw" | "structure.publication.prepare.get" | "structure.content-key.history.jobs.read" | "structure.content-key.history.get" | "structure.content-key.history.deliver" | "structure.publication.set" | "structure.publication.entry.set" | "structure.access.approval.get" | "structure.access.end" | "structure.instance.resolve" | "structure.workspace.create" | "structure.workspace.get" | "structure.adopt" | "structure.action"
        | "structure.instance.get" | "structure.record.get" | "structure.operation.get"
        | "structure.member.set" | "structure.grant.set" | "structure.grant.revoke" | "structure.grant.get"
        | "structure.members.read" | "structure.instances.read" | "structure.records.read" | "structure.events.read"
        | "structure.maintenance.rebuild" | "structure.maintenance.get" | "structure.maintenance.cancel" | "structure.operations.read" | "structure.access.authorize" | "structure.content-keys.read" | "structure.content-key.set" | "structure.content-key.get" | "structure.content-key.delivery.get" | "structure.content-key.deliver")
}
