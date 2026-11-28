"""Deterministic Responses API for the real Codex handoff test."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import re
import sys
import time


def objects(value):
    if isinstance(value, str):
        try:
            decoded = json.loads(value.split("\nOutput:\n", 1)[-1])
        except ValueError:
            return
        if not isinstance(decoded, str):
            yield from objects(decoded)
    elif isinstance(value, list):
        for item in value:
            yield from objects(item)
    elif isinstance(value, dict):
        yield value
        for item in value.values():
            yield from objects(item)


class Model(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_POST(self):
        if not self.path.endswith('/responses'):
            self.send_error(404)
            return
        request = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        tools = {}
        for tool in request.get('tools', []):
            for member in tool.get('tools', []):
                tools[member['name']] = tool.get('name')
            if tool.get('type') == 'function':
                tools[tool['name']] = None
        history = request.get('input', [])
        user_index = max((i for i, m in enumerate(history) if m.get('role') == 'user'), default=-1)
        output = history[user_index+1:]
        batch = None
        if user_index >= 0:
            message = json.dumps(history[user_index].get('content'), ensure_ascii=False).replace('\\"','"')
            batch = re.search(r'"batch"\s*:\s*"([A-Za-z0-9_-]{43})"', message)
        seen = set()
        next_action = None
        results = []
        for obj in objects(output):
            if obj.get('type') == 'function_call' and str(obj.get('name','')).endswith('peerwork_reply'):
                arguments = json.loads(obj.get('arguments','{}'))
                seen.add(arguments.get('operation_id'))
            if 'state' in obj or 'error' in obj or 'code' in obj:
                results.append({k:obj[k] for k in ('state','code','operation_id','error') if k in obj})
        for obj in objects(output):
            if not isinstance(obj.get('items'), list) or not isinstance(obj.get('scope'), str):
                continue
            for item in obj['items']:
                message = item['message']
                match = re.fullmatch(r'PING (HANDOFF-[12])', message.get('text',''))
                if not match or message.get('assurance') != 'AUTHOR_SIGNATURE_AND_AEAD' or not message.get('can_reply'):
                    continue
                nonce = match[1]
                operation = 'fixture-reply-' + nonce
                if operation not in seen:
                    next_action = ('peerwork_reply', {'scope': obj['scope'], 'item': item['item'], 'operation_id': operation, 'text': 'PONG '+nonce, 'wait_ms':5000})
                    break
            if next_action:
                break
        if next_action is None and batch and not any(m.get('type') in ('function_call_output','mcp_call') for m in output):
            next_action = ('peerwork_inbox', {'batch': batch[1]})
        call = next_action and next((name for name in tools if name.endswith(next_action[0])), None)
        uid = str(time.time_ns())
        item = {'id':'fc_'+uid,'type':'function_call','name':call,'arguments':json.dumps(next_action[1]),'call_id':'call_'+uid,'status':'completed'} if call else {'id':'msg_'+uid,'type':'message','role':'assistant','status':'completed','content':[{'type':'output_text','text':'Fixture processed.','annotations':[]}]}
        if call and tools[call]:
            item['namespace'] = tools[call]
        self.send_response(200)
        self.send_header('content-type','text/event-stream')
        self.end_headers()

        def emit(kind, **value):
            self.wfile.write(('event: '+kind+'\ndata: '+json.dumps(dict(type=kind,**value))+'\n\n').encode())

        emit('response.created', response={'id':'resp_'+uid,'object':'response','status':'in_progress','output':[]})
        if call:
            emit('response.output_item.added', output_index=0, item=dict(item,arguments='',status='in_progress'))
            emit('response.function_call_arguments.delta', item_id=item['id'], output_index=0, delta=item['arguments'])
            emit('response.function_call_arguments.done', item_id=item['id'], output_index=0, arguments=item['arguments'])
        else:
            emit('response.output_item.added', output_index=0, item=dict(item,status='in_progress',content=[]))
            emit('response.content_part.added', item_id=item['id'], output_index=0, content_index=0, part={'type':'output_text','text':'','annotations':[]})
            emit('response.output_text.delta', item_id=item['id'], output_index=0, content_index=0, delta='Fixture processed.')
            emit('response.output_text.done', item_id=item['id'], output_index=0, content_index=0, text='Fixture processed.')
            emit('response.content_part.done', item_id=item['id'], output_index=0, content_index=0, part=item['content'][0])
        emit('response.output_item.done', output_index=0, item=item)
        emit('response.completed', response={'id':'resp_'+uid,'object':'response','status':'completed','output':[item],'usage':{'input_tokens':1,'output_tokens':1,'total_tokens':2}})
        outputs = [m.get('output') for m in output if m.get('type') in ('function_call_output','mcp_call')]
        print(json.dumps({'batch': bool(batch), 'tool': next_action[0] if call else None, 'results':results[-5:], 'output_types':[m.get('type') for m in output], 'last_output':str(outputs[-1:])[:650]}), flush=True)


server = ThreadingHTTPServer(('127.0.0.1',0), Model)
Path(sys.argv[1]).write_text(str(server.server_port)+'\n')
server.serve_forever()
