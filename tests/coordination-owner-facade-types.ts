import type { SecureOwnerWorkspaceSession, OwnerCoordinationProgress } from '../bindings/node/index';
declare const owner: SecureOwnerWorkspaceSession;
const enable: Promise<OwnerCoordinationProgress> = owner.enableCoordination('workspace', {version:2, participants:[]});
const omitted = owner.enableCoordination('workspace');
const resume: Promise<OwnerCoordinationProgress> = owner.resumeCoordination('workspace', 'original-BEGIN');
const history: Promise<OwnerCoordinationProgress[]> = owner.coordinationOperations('workspace');
enable.then(value => {
  const status: 'PENDING' | 'ACCEPTED' = value.status;
  const version: 1 | 2 = value.version;
  const nullable: (string | null)[] = [value.begin_command_id, value.step_command_id,
    value.step_action_id, value.head, value.policy_hash];
  const sequence: number | null = value.sequence;
  void [status, version, nullable, sequence, value.workspace_id, value.instance_id, value.protocol_digest];
});
// @ts-expect-error only supported versions are accepted
owner.enableCoordination('workspace', {version:3});
// @ts-expect-error coordination does not accept caller material
owner.enableCoordination('workspace', {material:{}});
// @ts-expect-error participants are actor IDs, not a single string
owner.enableCoordination('workspace', {participants:'actor'});
// @ts-expect-error recovery requires the original BEGIN ID
owner.resumeCoordination('workspace');
void [enable, omitted, resume, history];
