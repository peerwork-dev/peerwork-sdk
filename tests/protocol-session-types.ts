import {protocolSession, type KernelSession, type ProtocolSessionBinding, type PreparedProtocolAction} from '../bindings/node/index';
export async function participant(kernel: KernelSession, binding: ProtocolSessionBinding) {
  const session = protocolSession(kernel, binding);
  const view = await session.describe();
  if (!view.context) return view.outcome;
  const state = await session.state();
  if (state.state !== 'ACCEPTED' && state.state !== 'COMPLETED') return state;
  const prepared: PreparedProtocolAction = session.prepareAction({
    tool: 'work_announce', values: {scope: 'parser', summary: 'Check parser', ttl_ms: 60000},
    expected_revision: 1, operation_id: 'stable-operation',
  });
  await session.records({limit: 8, schema: 'finding'});
  await session.updates({after_sequence: 0, limit: 8});
  await session.record({record_id: 'selected-record', revision: 1});
  return session.resume(prepared);
}
