"""Explicit delivery control API. The shared connector process owns receiving."""
# SPDX-License-Identifier: Apache-2.0
import copy
from .protocol_session import ProtocolSession

class DeliveryClient:
    def __init__(self, kernel, binding):
        self._session = ProtocolSession(kernel, binding)
        self.kernel = kernel

    def _call(self, action, body, operation_id=None):
        self._session._assert_kernel()
        b = self._session.binding
        intent = dict(action='structure.delivery.' + action,
                      workspace_id=b['workspace_id'], instance_id=b['instance_id'],
                      protocol_digest=b['protocol_digest'], body=copy.deepcopy(body))
        if operation_id is not None:
            intent['idempotency_key'] = operation_id
        return self._session._check_result(self.kernel.execute_structure_intent(intent))

    def claim(self, selection, *, operation_id):
        b = self._session.binding
        return self._call('route.claim', {**selection, 'package_digest': b['package_digest'], 'role': b['role']}, operation_id)

    def close(self, fence, *, operation_id):
        return self._call('route.close', fence, operation_id)

    def get(self, route_id):
        return self._call('route.get', dict(route_id=route_id))

    def routes(self, *, limit=16, after=None):
        return self._call('routes.read', dict(limit=limit, after=after))

    def receipt(self, route_id, sequence):
        return self._call('receipt.get', dict(route_id=route_id, sequence=sequence))

    def pulse(self, selection):
        return self._call('pulse', selection)

    def ack(self, selection):
        return self._call('ack', selection)

    def inbox(self, selection):
        return self._call('inbox.read', selection)

    def stream_token(self, fence):
        return self._call('stream.get', fence)
