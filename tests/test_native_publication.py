"""Regression checks for evidence-copy preservation and publication privacy."""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
import zipfile

from research.native import publication as p


class PublicationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def original(self, contents=None):
        contents = contents or {'original.jsonl': self.event(), 'data.sqlite': b'SQLite unchanged test bytes'}
        raw = io.BytesIO()
        manifest = {'files': {name: {'sha256': p.sha(data), 'bytes': len(data)}
                              for name, data in contents.items()}}
        with zipfile.ZipFile(raw, 'w') as z:
            for name, data in contents.items():
                p.put(z, name, data)
            p.put(z, 'review-manifest.json', p.encoded(manifest))
        path = self.root / 'original.zip'
        path.write_bytes(raw.getvalue())
        return path, p.sha(raw.getvalue())

    def event(self):
        return b'{"type":"event_msg","payload":{"type":"token_count","info":{"tokens":123},"rate_limits":{"credits":{"balance":"private"},"primary":{"used_percent":23}}}}\n'

    def test_only_account_value_changes(self):
        original = self.event()
        new, changes = p.scrub_usage(original)
        a, b = json.loads(original), json.loads(new)
        a['payload']['rate_limits'] = None
        self.assertEqual(a, b)
        self.assertIn(b'"info":{"tokens":123}', new)
        self.assertEqual(changes[0]['line'], 1)
        self.assertEqual(changes[0]['original_line_sha256'], p.sha(original))

    def test_non_account_lines_and_newlines_unchanged(self):
        before = b'{"type":"response_item","payload":{"command":"rm example"}}\r\n'
        after = b'not json\n'
        new, changes = p.scrub_usage(before + self.event() + after)
        self.assertTrue(new.startswith(before) and new.endswith(after))
        self.assertEqual([v['line'] for v in changes], [2])

    def test_idempotent_redaction(self):
        new, _ = p.scrub_usage(self.event())
        self.assertEqual(p.scrub_usage(new), (new, []))

    def test_reject_unexpected_rate_limit_record(self):
        with self.assertRaisesRegex(ValueError, 'Unrecognized'):
            p.scrub_usage(b'{"payload":{"rate_limits":{"used":1}}}\n')

    def test_reject_ambiguous_key(self):
        data = self.event().replace(b'"info":{"tokens":123}', b'"info":{"rate_limits":1}')
        with self.assertRaisesRegex(ValueError, 'Ambiguous'):
            p.scrub_usage(data)

    def test_original_hash_required(self):
        source, _ = self.original()
        with self.assertRaisesRegex(ValueError, 'Original archive'):
            p.build_archive(source, self.root / 'public.zip', '0' * 64)

    def test_original_and_sqlite_preserved(self):
        source, digest = self.original()
        raw = source.read_bytes()
        target = self.root / 'public.zip'
        result = p.build_archive(source, target, digest)
        self.assertEqual(source.read_bytes(), raw)
        self.assertEqual(result['redacted_files'], 1)
        self.assertEqual(result['redacted_usage_events'], 1)
        with zipfile.ZipFile(source) as a, zipfile.ZipFile(target) as b:
            self.assertEqual(a.read('data.sqlite'), b.read('data.sqlite'))
            self.assertEqual(a.read('review-manifest.json'), b.read('review-manifest.json'))
        self.assertEqual(result, p.build_archive(source, target, digest))

    def test_existing_different_public_copy_retained(self):
        source, digest = self.original()
        target = self.root / 'public.zip'
        target.write_bytes(b'earlier copy')
        with self.assertRaisesRegex(ValueError, 'already exists'):
            p.build_archive(source, target, digest)
        self.assertEqual(target.read_bytes(), b'earlier copy')

    def test_no_account_values_in_public_zip(self):
        source, digest = self.original()
        target = self.root / 'public.zip'
        p.build_archive(source, target, digest)
        with zipfile.ZipFile(target) as z:
            self.assertFalse(any(b'"balance"' in z.read(n) for n in z.namelist()))

    def test_known_credential_blocks_even_opaque_blob(self):
        secret = b'known-credential-value'
        row = {'type': 'response_item', 'payload': {'type': 'reasoning',
               'encrypted_content': secret.decode()}}
        with self.assertRaisesRegex(ValueError, 'Known credential'):
            p.credential_scan('rollout.jsonl', json.dumps(row).encode(), [secret])

    def test_regex_credential_outside_opaque_reasoning_blocked(self):
        token = 'sk-proj-' + 'x' * 40
        with self.assertRaisesRegex(ValueError, 'Possible credential'):
            p.credential_scan('rollout.jsonl', json.dumps({'output': token}).encode())
        row = {'type': 'response_item', 'payload': {'type': 'reasoning', 'encrypted_content': token}}
        p.credential_scan('rollout.jsonl', json.dumps(row).encode())

    def test_private_field_and_auth_filename_blocked(self):
        with self.assertRaisesRegex(ValueError, 'private account'):
            p.credential_scan('rollout.jsonl', b'{"email":"person@example.test"}')
        with self.assertRaisesRegex(ValueError, 'Credential-file'):
            p.credential_scan('nested/auth.json', b'{}')

    def test_original_usage_must_be_redacted(self):
        with self.assertRaisesRegex(ValueError, 'not redacted'):
            p.credential_scan('rollout.jsonl', self.event())

    def test_path_traversal_and_symlink_rejected(self):
        for name, mode in [('../x', 0), ('/x', 0), ('x\\y', 0), ('x', 0o120777)]:
            with self.subTest(name=name), self.assertRaises(ValueError):
                p.member(name, mode)

    def test_tampered_member_rejected(self):
        source, digest = self.original()
        target = self.root / 'public.zip'
        p.build_archive(source, target, digest)
        with zipfile.ZipFile(target) as z:
            contents = {n: z.read(n) for n in z.namelist()}
        contents['data.sqlite'] = b'changed'
        with zipfile.ZipFile(target, 'w') as z:
            for n, data in contents.items():
                p.put(z, n, data)
        with self.assertRaisesRegex(ValueError, 'Unchanged original member'):
            p.verify_archive(target, digest)

    def test_removal_of_archive_member_rejected(self):
        source, digest = self.original()
        target = self.root / 'public.zip'
        p.build_archive(source, target, digest)
        with zipfile.ZipFile(target) as z:
            contents = {n: z.read(n) for n in z.namelist() if n != 'data.sqlite'}
        with zipfile.ZipFile(target, 'w') as z:
            for n, data in contents.items():
                p.put(z, n, data)
        with self.assertRaisesRegex(ValueError, 'membership'):
            p.verify_archive(target, digest)

    def test_rate_limit_value_is_not_copied_to_manifest(self):
        source, digest = self.original()
        target = self.root / 'public.zip'
        p.build_archive(source, target, digest)
        with zipfile.ZipFile(target) as z:
            manifest = json.loads(z.read('publication-manifest.json'))
        change = manifest['changed_files']['original.jsonl']['changes'][0]
        self.assertEqual(set(change), {'line', 'json_path', 'original_line_sha256', 'public_line_sha256'})


if __name__ == '__main__':
    unittest.main()
