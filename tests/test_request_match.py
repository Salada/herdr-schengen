"""Unit tests for the directional request-command matcher (adapters/request_match.py).

AGENTS.md rule 14 (TOCTOU guard fuzzy/prefix matching, incidents #3143/#3219):
the live pane-text re-parse may be a viewport-soft-wrap TRUNCATED prefix of the
gatekeeper-evaluated full command, or an access_directory path-expression
variant (`~` vs absolute, parent dir vs file, glob vs concrete). The matcher
must tolerate those while NEVER matching a screen that GREW beyond the approved
command (agent appended a dangerous superset).
"""

import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

SCRIPT_DIR = Path(__file__).parent.parent / "scripts"
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import adapters.request_match as rm
from adapters.request_match import norm_req_cmd, same_request


def setUpModule():
    # Pin the prefix minimum: these tests assume the documented default of 16
    # regardless of a host SCHENGEN_PREFIX_MATCH_MIN_LEN override (the module
    # constant is read from the environment once at import time; the functions
    # resolve it as a module global on every call, so mutation is sufficient).
    rm.MIN_PREFIX_LEN = 16


class TestNormReqCmdUnchanged(unittest.TestCase):
    """Parity with TestNormReqCmd (test_opencode_target.py): normalization stays
    SURGICAL (prompt + whitespace only), never security-collapsing."""

    def test_prompt_prefix_and_whitespace_still_match(self):
        self.assertEqual(
            norm_req_cmd("$ python3 -m unittest discover -s tests"),
            norm_req_cmd("python3 -m unittest discover -s tests"),
        )
        self.assertEqual(norm_req_cmd("  ls   -la  "), norm_req_cmd("ls -la"))

    def test_different_paths_do_not_normalize_equal(self):
        self.assertNotEqual(
            norm_req_cmd("edit_file /Users/alice/foo.txt"),
            norm_req_cmd("edit_file /Users/alice/.ssh/id_rsa"),
        )
        self.assertNotEqual(
            norm_req_cmd("cat /home/bob/a.txt"),
            norm_req_cmd("cat /home/bob/.aws/credentials"),
        )

    def test_quoted_payloads_do_not_normalize_equal(self):
        self.assertNotEqual(
            norm_req_cmd('python3 -c "print(1)"'),
            norm_req_cmd('python3 -c "print(2)"'),
        )


class TestSameRequestBasic(unittest.TestCase):
    def test_exact_equal_matches(self):
        self.assertTrue(same_request("ls -la", "ls -la"))
        # Leading '$ ' prompt / whitespace variance of the SAME command matches.
        self.assertTrue(same_request("ls -la", "$  ls   -la"))

    def test_truncated_prefix_matches(self):
        # Issue #3143/#3219: the live re-parse is a viewport-soft-wrap truncated
        # PREFIX of the approved command -> the dialog is still the SAME request.
        self.assertTrue(same_request("git status --porcelain", "git status"))

    def test_superset_does_not_match(self):
        # Directionality (fail-closed): a live re-parse that GREW beyond the
        # approved command (agent appended '&& rm -rf /') must NEVER match.
        self.assertFalse(same_request("git status", "git status --porcelain && rm -rf /"))

    def test_short_prefix_rejected(self):
        # The approved command is too short to have been viewport-wrapped; a
        # shorter screen is a DIFFERENT request (MIN_PREFIX_LEN gate).
        self.assertFalse(same_request("ls -la /tmp/foo", "ls"))

    def test_mid_token_prefix_rejected(self):
        # A meaningful wrap cut lands at a whitespace boundary; a mid-token cut
        # is not a rendering artifact -> fail-closed (defer -> full re-parse).
        self.assertFalse(same_request("python3 -m unittest discover -s tests", "python3 -m unittest discover -s te"))

    def test_empty_screen_rejected(self):
        self.assertFalse(same_request("ls", ""))
        self.assertFalse(same_request("", "ls"))
        self.assertFalse(same_request(None, "ls"))
        self.assertFalse(same_request(None, None))


class TestSameRequestAccessDir(unittest.TestCase):
    """access_directory path-expression variance of the SAME directory grant."""

    def test_access_dir_parent_dir_matches(self):
        # Screen re-parsed as the PARENT directory of the approved concrete path.
        self.assertTrue(same_request("access_directory /a/b/c/tui.py", "access_directory /a/b/c"))

    def test_access_dir_glob_matches(self):
        # Screen rendered as a glob covering the approved concrete path.
        self.assertTrue(same_request("access_directory /a/b/c/tui.py", "access_directory /a/b/c/*"))

    def test_access_dir_tilde_vs_absolute(self):
        # '~' vs absolute spelling of the same directory grant.
        with patch.dict(os.environ, {"HOME": "/home/schengen"}):
            self.assertTrue(
                same_request("access_directory ~/src/tui.py", "access_directory /home/schengen/src")
            )
            # Same directory spelled both ways (tilde == absolute root) matches.
            self.assertTrue(
                same_request("access_directory ~/src", "access_directory /home/schengen/src")
            )

    def test_access_dir_non_ancestor_rejected(self):
        # A grant on /a/c is NOT the same grant as /a/b (sibling, not ancestor).
        self.assertFalse(same_request("access_directory /a/b", "access_directory /a/c"))

    def test_access_dir_deeper_subdir_rejected(self):
        # approved is the PARENT, screen the CHILD (superset direction): the live
        # request asks for MORE than was approved -> different grant.
        self.assertFalse(same_request("access_directory /a/b", "access_directory /a/b/c/tui.py"))


class TestSameRequestNonRelaxed(unittest.TestCase):
    """Path-semantic (parent/glob) relaxation is access_directory ONLY.

    edit_file / read_file get no upper-directory / glob tolerance. NOTE: a
    parent-directory screen IS a plain text prefix of any file beneath it, so a
    literal parent negative is not expressible — the generic whitespace-boundary
    prefix tolerance applies to all kinds by design. The true invariant tested
    here: non-prefix path VARIANTS (sibling leaf, glob) of edit_file / read_file
    are NOT the same request.
    """

    def test_edit_file_sibling_mismatch_rejected(self):
        # Same parent, different leaf: approved foo.py, dialog now shows bar.py.
        self.assertFalse(same_request("edit_file /a/b/c/foo.py", "edit_file /a/b/c/bar.py"))

    def test_edit_file_glob_mismatch_rejected(self):
        # A glob screen never matches the approved concrete edit target.
        self.assertFalse(same_request("edit_file /a/b/c/tui.py", "edit_file /a/b/c/*"))

    def test_read_file_glob_mismatch_rejected(self):
        self.assertFalse(same_request("read_file /a/b/secret.txt", "read_file /a/b/*.txt"))

    def test_different_bash_paths_rejected(self):
        # cat a.txt vs cat .aws/credentials share a prefix but diverge -> the
        # live re-parse is a DIFFERENT command (not a same-dialog prefix).
        self.assertFalse(same_request("cat /home/bob/a.txt", "cat /home/bob/.aws/credentials"))

    def test_edit_file_exact_match_still_true(self):
        # Sanity: identical edit_file requests still match.
        self.assertTrue(same_request("edit_file /a/b/c/tui.py", "edit_file /a/b/c/tui.py"))


if __name__ == "__main__":
    unittest.main()
