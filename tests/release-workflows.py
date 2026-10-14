"""Offline CI policy/packaging regressions; synthetic Apple/CI responses only.

No native build, actual signature/notary, auth lookup or publication is run.
"""
import importlib.util
import io
import json
import re
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools/release'))
import assets,stage,version

def load(name):
    spec=importlib.util.spec_from_file_location(name,ROOT/'tools/release'/(name+'.py'));module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
ci=load('ci-verify');mac=load('macos-sign');finalize=load('finalize');publisher=load('publication-inputs');builder=load('build')
SOURCE='a'*40;EPOCH=1791979200

class WorkflowGuards(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup);self.work=Path(temporary.name);self.keychain=self.work/'synthetic.keychain';self.keychain.write_bytes(b'not a real keychain')
        self.source=patch.object(stage,'source',return_value=(SOURCE,EPOCH));self.source.start();self.addCleanup(self.source.stop)
    def seal(self,directory):
        manifest=json.loads((directory/'release.json').read_text())
        manifest['assets']={name:value for name,value in assets.inventory(directory).items() if name not in {'release.json','SHA256SUMS'}}
        (directory/'release.json').write_bytes(assets.wire(manifest))
        self.sums(directory)
    def sums(self,directory):
        (directory/'SHA256SUMS').write_text(''.join(value['sha256']+'  '+name+'\n' for name,value in sorted(assets.inventory(directory).items()) if name!='SHA256SUMS'))
    def unsigned(self):
        directory=self.work/'unsigned';directory.mkdir();targets={}
        for target in version.TARGETS:
            names=['peerwork_sdk-0.0.1-cp311-abi3-'+assets.WHEEL_PLATFORM[target]+'.whl','peerwork-agent-sdk-'+target+'-0.0.1.tgz','peerwork-agent-sdk-0.0.1.tgz','peerwork-0.0.1-'+target+'.tar.gz']
            for name in names:(directory/name).write_bytes(b'synthetic unexecuted target')
            (directory/('sbom-'+target+'.spdx.json')).write_bytes(b'{}')
            (directory/('licenses-'+target+'.json')).write_bytes(b'{}')
            targets[target]=dict(bundle_manifest_sha256='b'*64,package_assets=names)
            if target.startswith('darwin'):
                binary=bytearray(64);binary[:4]=b'\xcf\xfa\xed\xfe';struct.pack_into('<I',binary,4,0x100000c if target.endswith('arm64') else 0x1000007)
                with zipfile.ZipFile(directory/names[0],'w') as archive:
                    archive.writestr('peerwork/_native.abi3.so',binary);archive.writestr('peerwork/LICENSE',b'unchanged notice');archive.writestr('peerwork_sdk-0.0.1.dist-info/RECORD',b'')
                for name,files in [(names[1],{'package/index.node':bytes(binary),'package/LICENSE':b'unchanged notice'}),(names[3],{'peerwork':bytes(binary),'LICENSE':b'unchanged notice'})]:assets.deterministic_tar(directory/name,{n:(data,0o755 if n=='peerwork' else 0o644) for n,data in files.items()},EPOCH)
        manifest=dict(version='0.0.1',tag='v0.0.1',source_commit=SOURCE,source_date_epoch=EPOCH,unsigned=True,targets=targets,assets={})
        (directory/'release.json').write_bytes(assets.wire(manifest));self.seal(directory);return directory
    def apple(self,command,**kwargs):
        if command[0]=='codesign' and '--sign' in command:
            self.assertEqual(command[command.index('--keychain')+1],str(self.keychain))
            path=Path(command[-1]);path.write_bytes(path.read_bytes()+b'mocked-signature')
        if command[0]=='xcrun':
            self.assertEqual(command[command.index('--keychain')+1],str(self.keychain));self.assertIn('--wait',command)
        return subprocess.CompletedProcess(command,0,stdout=json.dumps(dict(status='Accepted',id='12345678-1234-1234-1234-123456789abc')),stderr='')
    def sign_pair(self,unsigned):
        directory=self.work/'signed';directory.mkdir()
        with patch.object(mac.ci,'verify_subject'),patch.object(mac.subprocess,'run',side_effect=self.apple):
            for target in ['darwin-x64','darwin-arm64']:mac.sign(ROOT,unsigned,target,directory/('release-signed-'+target),'synthetic Developer ID','synthetic-profile','v0.0.1','owner/repo',self.keychain)
        return directory
    def test_exact_provenance_command_policy_and_fail_closed(self):
        path=self.work/'artifact';path.write_bytes(b'bytes')
        with patch.object(ci.subprocess,'run',return_value=subprocess.CompletedProcess([],0,'[{}]','')) as run:
            result=ci.verify_subject(path,'owner/repo',SOURCE,'v0.0.1')
            args=run.call_args.args[0]
            for flag,value in [('--repo','owner/repo'),('--signer-workflow','owner/repo/.github/workflows/release-build.yml'),('--signer-digest',SOURCE),('--source-digest',SOURCE),('--source-ref','refs/tags/v0.0.1')]:self.assertEqual(args[args.index(flag)+1],value)
            self.assertIn('--deny-self-hosted-runners',args);self.assertEqual(result['sha256'],assets.sha(path))
        for code,out in [(1,'[]'),(0,'[]'),(0,'{}')]:
            with patch.object(ci.subprocess,'run',return_value=subprocess.CompletedProcess([],code,out,'not printed')),self.assertRaises(version.ReleaseError):ci.verify_subject(path,'owner/repo',SOURCE,'v0.0.1')
    def test_all_target_assembly_uses_unique_flat_dependency_names(self):
        bundles=self.work/'bundles';bundles.mkdir();verified={}
        for target in version.TARGETS:
            directory=bundles/target;directory.mkdir();names=['wheel-'+target+'.whl','native-'+target+'.tgz','wrapper.tgz','cli-'+target+'.tar.gz']
            for name in names:(directory/name).write_bytes(b'wrapper' if name=='wrapper.tgz' else name.encode())
            (directory/'sbom.spdx.json').write_bytes(target.encode());(directory/'licenses.json').write_bytes(target.encode());(directory/'release.json').write_bytes(b'{}')
            verified[target]=dict(target=target,release_eligible=True,package_assets=names)
        output=self.work/'assembled'
        with patch.object(stage,'verify',side_effect=lambda directory,root:verified[directory.name]):manifest=stage.assemble(ROOT,bundles,output,'v0.0.1')
        self.assertEqual(len(manifest['assets']),36);self.assertTrue(all('/' not in name for name in manifest['assets']))
        for target in version.TARGETS:self.assertEqual((output/('sbom-'+target+'.spdx.json')).read_bytes(),target.encode())
        # Synthetic already-verified maps isolate filename assembly only.
        self.assertFalse(any(p.is_dir() for p in output.iterdir()))
    def test_unsigned_tamper_blocks_before_apple_commands(self):
        unsigned=self.unsigned();(unsigned/'licenses-darwin-x64.json').write_bytes(b'changed')
        with patch.object(mac.subprocess,'run') as run,self.assertRaises(version.ReleaseError):mac.sign(ROOT,unsigned,'darwin-x64',self.work/'rejected','synthetic','profile','v0.0.1','owner/repo',self.keychain)
        run.assert_not_called();self.assertFalse((self.work/'rejected').exists())
    def test_failed_notarization_never_emits_signed_output(self):
        unsigned=self.unsigned()
        def rejected(command,**kwargs):
            if command[0]=='xcrun':return subprocess.CompletedProcess(command,0,json.dumps(dict(status='Invalid',id='12345678-1234-1234-1234-123456789abc')),'')
            return self.apple(command,**kwargs)
        with patch.object(mac.ci,'verify_subject'),patch.object(mac.subprocess,'run',side_effect=rejected),self.assertRaisesRegex(version.ReleaseError,'not accepted'):mac.sign(ROOT,unsigned,'darwin-x64',self.work/'rejected','synthetic','profile','v0.0.1','owner/repo',self.keychain)
        self.assertFalse((self.work/'rejected').exists())
    def test_signature_failure_never_submits_notarization(self):
        unsigned=self.unsigned();commands=[]
        def rejected(command,**kwargs):
            commands.append(command)
            if '--verify' in command:raise subprocess.CalledProcessError(1,command)
            return self.apple(command,**kwargs)
        with patch.object(mac.ci,'verify_subject'),patch.object(mac.subprocess,'run',side_effect=rejected),self.assertRaises(subprocess.CalledProcessError):mac.sign(ROOT,unsigned,'darwin-x64',self.work/'rejected','synthetic','profile','v0.0.1','owner/repo',self.keychain)
        self.assertFalse(any(c[0]=='xcrun' for c in commands));self.assertFalse((self.work/'rejected').exists())
    def test_mocked_signature_binding_record_finalization_and_publisher_closure(self):
        unsigned=self.unsigned();signed=self.sign_pair(unsigned);output=self.work/'final'
        with patch.object(finalize.ci,'verify_subject'):result=finalize.finalize(ROOT,unsigned,signed,output,'owner/repo','v0.0.1')
        self.assertFalse(result['unsigned']);self.assertEqual(len(result['assets']),38);self.assertTrue(all('/' not in name for name in result['assets']))
        with patch.object(publisher.ci,'verify_subject'):inputs=publisher.prepare(ROOT,output,self.work/'publish','owner/repo','v0.0.1')
        self.assertEqual(len(inputs['python_wheels']),7);self.assertEqual(len(inputs['node_packages']),8);self.assertEqual(inputs['node_packages'][-1],'peerwork-agent-sdk-0.0.1.tgz')
        self.assertFalse(inputs['registry_atomicity'])
        (output/'unexpected').write_bytes(b'extra')
        with patch.object(publisher.ci,'verify_subject'),self.assertRaisesRegex(version.ReleaseError,'closure'):publisher.prepare(ROOT,output,self.work/'rejected-extra','owner/repo','v0.0.1')
        self.assertFalse((self.work/'rejected-extra').exists())
    def test_resealed_signed_notice_substitution_blocks_finalization(self):
        unsigned=self.unsigned();signed=self.sign_pair(unsigned);directory=signed/'release-signed-darwin-x64';path=directory/'peerwork-agent-sdk-darwin-x64-0.0.1.tgz'
        files=assets.tar_members(path);files['package/LICENSE']=b'substituted notice';assets.deterministic_tar(path,{name:(data,0o644) for name,data in files.items()},EPOCH)
        receipt=json.loads((directory/'macos-signing.json').read_text());row=next(row for row in receipt['assets'] if row['name']==path.name);row['signed_sha256']=assets.sha(path);row['signed_bytes']=path.stat().st_size;(directory/'macos-signing.json').write_bytes(assets.wire(receipt));self.sums(directory)
        with patch.object(finalize.ci,'verify_subject'),self.assertRaisesRegex(version.ReleaseError,'package data'):finalize.finalize(ROOT,unsigned,signed,self.work/'rejected','owner/repo','v0.0.1')
        self.assertFalse((self.work/'rejected').exists())
    def test_missing_signing_target_and_final_extra_block(self):
        unsigned=self.unsigned();signed=self.sign_pair(unsigned);shutil.rmtree(signed/'release-signed-darwin-arm64')
        with self.assertRaisesRegex(version.ReleaseError,'both signed'):finalize.finalize(ROOT,unsigned,signed,self.work/'rejected','owner/repo','v0.0.1')
        self.assertFalse((self.work/'rejected').exists())
    def test_exact_linux_inputs_and_unchanged_runtime_source_boundary(self):
        inputs=json.loads((ROOT/'tools/release/build-inputs.json').read_text());self.assertEqual(set(inputs['linux']),{t for t in version.TARGETS if t.startswith('linux')});self.assertEqual(set(builder.TRIPLES),set(version.TARGETS))
        for target,p in inputs['linux'].items():
            self.assertRegex(p['rustup_sha256'],r'^[0-9a-f]{64}$')
            if target.endswith('gnu'):self.assertRegex(p['image'],r'^quay.io/pypa/manylinux_2_28_(x86_64|aarch64)@sha256:[0-9a-f]{64}$')
    def test_failed_native_byte_reproduction_blocks_assembly(self):
        directory=self.work/'replicas';directory.mkdir()
        for replica in ['1','2']:
            for target in version.TARGETS:
                bundle=directory/('release-unsigned-'+replica+'-'+target);bundle.mkdir();(bundle/'subject').write_bytes(replica.encode())
        output=self.work/'rejected-reproduction'
        with patch.object(stage,'verify',return_value=dict(target='linux-x64-gnu',release_eligible=True)),patch.object(ci,'verify_subject'),self.assertRaisesRegex(version.ReleaseError,'not reproducible'):ci.prepare(ROOT,directory,output,'owner/repo','v0.0.1')
        self.assertFalse(output.exists())
    def test_missing_signing_prerequisites_block_before_verification(self):
        with patch.object(mac.ci,'verify_subject') as verify,self.assertRaisesRegex(version.ReleaseError,'protected notarization keychain'):mac.sign(ROOT,self.work/'absent','darwin-x64',self.work/'rejected','synthetic','profile','v0.0.1','owner/repo',self.work/'absent.keychain')
        verify.assert_not_called();self.assertFalse((self.work/'rejected').exists())
    def test_hidden_output_uploads_are_explicit_and_finite(self):
        text=(ROOT/'.github/workflows/release.yml').read_text()
        blocks=re.findall(r'(?ms)^      - uses: actions/upload-artifact@[^\n]+\n(.*?)(?=^      - |^  [a-z_]+:|\Z)',text)
        self.assertEqual(len(blocks),3)
        found=set()
        for block in blocks:
            path=re.search(r'(?m)^          path: (.+)$',block).group(1)
            self.assertIn(path,{'.release-unsigned/**','.release-signed/*','.release-final/**'})
            self.assertIn('          include-hidden-files: true\n',block)
            self.assertIn('          if-no-files-found: error',block);found.add(path)
        self.assertEqual(len(found),3)
        # Private certificate/keychain material is created under RUNNER_TEMP;
        # every upload is limited to a separately checked release inventory.
        self.assertIn('$RUNNER_TEMP/peerwork-release.keychain-db',text)
        self.assertIn('pathlib.Path(os.environ["RUNNER_TEMP"],"developer-id.p12")',text)
if __name__=='__main__':unittest.main()
