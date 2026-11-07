#!/usr/bin/env python3
"""The corpus is the contract, and the fixture names are the expectations.

Each PHP function in tests/fixtures declares its own expected verdict in its
name, so adding a case is one function and no test code:

    want_C_*     must classify as C
    want_I_*     must classify as I
    want_Iq_*    must classify as I?
    want_A_*     must classify as A
    want_P_*     must classify as P
    want_none_*  must classify as "-"

The out-of-scope half matters more than the in-scope half. A classifier that
calls correct code a vulnerability costs its user a rejected report, which is
the thing this tool exists to prevent.

    python3 -m unittest discover -s tests
"""

from __future__ import annotations

import io
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sinkclass import IN_SCOPE, MEANING, OUT_OF_SCOPE, classify  # noqa: E402
from sinkclass import classify_file, php  # noqa: E402
from sinkclass.cli import (EXIT_ERROR, EXIT_IN_SCOPE, EXIT_OUT_OF_SCOPE,  # noqa: E402
                           EXIT_UNDECIDED, main)

HERE = Path(__file__).parent
FIXTURES = HERE / "fixtures"
PLUGIN = HERE / "plugin"
EXAMPLE = HERE.parent / "examples" / "acme-booking"

PREFIX = {"want_C_": "C", "want_I_": "I", "want_Iq_": "I?",
          "want_A_": "A", "want_P_": "P", "want_none_": "-"}


def expected(name):
    """The verdict a fixture's own name demands, or None if it is a helper."""
    for prefix in sorted(PREFIX, key=len, reverse=True):
        if name.startswith(prefix):
            return PREFIX[prefix]
    return None


class Corpus(unittest.TestCase):
    """Every want_* function in the flat fixtures, classified with no root."""

    def _run(self, filename):
        path = FIXTURES / filename
        self.assertTrue(path.is_file(), "missing fixture %s" % filename)
        checked = 0
        for name, verdict in classify_file(str(path)):
            want = expected(name)
            if want is None:
                continue
            checked += 1
            self.assertEqual(
                verdict.code, want,
                "%s:%s expected %s, got %s (%s)"
                % (filename, name, want, verdict.code, verdict.why))
        self.assertGreater(checked, 0, "no want_* functions found in %s" % filename)
        return checked

    def test_in_scope_fixtures_all_fire(self):
        self.assertGreaterEqual(self._run("in_scope.php"), 11)

    def test_out_of_scope_fixtures_stay_out_of_scope(self):
        self.assertGreaterEqual(self._run("out_of_scope.php"), 8)

    def test_undecided_fixtures_say_so(self):
        self.assertGreaterEqual(self._run("undecided.php"), 4)

    def test_every_fixture_function_declares_an_expectation(self):
        """A fixture nobody asserts on is dead weight, so fail on one."""
        for path in sorted(FIXTURES.glob("*.php")):
            text = path.read_text(encoding="utf-8")
            for name in php.bodies(text):
                self.assertIsNotNone(
                    expected(name),
                    "%s:%s has no want_ prefix, so nothing asserts on it"
                    % (path.name, name))


class CalleeFollowing(unittest.TestCase):
    """The sink is usually one call below the handler."""

    def test_sink_one_hop_down_is_found_with_a_root(self):
        rows = dict(classify_file(str(PLUGIN / "handlers.php"), str(PLUGIN)))
        self.assertEqual(rows["want_I_sink_one_hop_down"].code, "I")
        self.assertEqual(rows["want_A_drain_one_hop_down"].code, "A")

    def test_mitigation_in_a_static_delegate_is_found(self):
        """An allowlist behind Class::method() once read as an arbitrary write."""
        rows = dict(classify_file(str(PLUGIN / "handlers.php"), str(PLUGIN)))
        self.assertEqual(rows["want_A_allowlist_in_a_static_delegate"].code, "A")

    def test_without_a_root_it_reports_seeing_nothing(self):
        """The negative control: no root, no index, so no invented verdict."""
        rows = dict(classify_file(str(PLUGIN / "handlers.php"), None))
        self.assertEqual(rows["want_I_sink_one_hop_down"].code, "-")

    def test_depth_zero_disables_following(self):
        body = (PLUGIN / "handlers.php").read_text(encoding="utf-8")
        name = "want_I_sink_one_hop_down"
        one = php.bodies(body)[name]
        self.assertEqual(classify(one, str(PLUGIN), depth=0).code, "-")
        self.assertEqual(classify(one, str(PLUGIN), depth=1).code, "I")

    def test_index_skips_vendor_and_tests(self):
        self.assertIn("acme_remove_file", php.index(str(PLUGIN)))


class ExampleStaysTrue(unittest.TestCase):
    """Every console block in the README is a real command, so pin its output."""

    def test_readme_example_verdicts(self):
        want = {
            "acme_export_users": "C",
            "acme_save_profile": "I",
            "acme_send_rating": "A",
        }
        table = php.index(str(EXAMPLE))
        got = {}
        for path in sorted(EXAMPLE.rglob("*.php")):
            got.update({name: verdict.code
                        for name, verdict in classify_file(str(path), table)})
        self.assertEqual({k: got.get(k) for k in want}, want)


class Precedence(unittest.TestCase):
    """Each of these orderings was wrong once."""

    def test_sql_injection_outranks_everything(self):
        body = ("global $wpdb; $id = $_GET['id'];"
                "$wpdb->query(\"DELETE FROM t WHERE id = $id\");"
                "wp_mail('a@example.com', 's', 'b');")
        self.assertEqual(classify(body).code, "C")

    def test_privileged_write_outranks_public_by_design(self):
        """An endpoint meant to be public is still a finding if it escalates."""
        body = ("retrieve_password($_POST['user_login']);"
                "update_option('default_role', 'administrator');")
        self.assertEqual(classify(body).code, "I")

    def test_prepared_statement_is_not_injection(self):
        body = ("$rows = $wpdb->get_results($wpdb->prepare("
                "\"SELECT user_email FROM u WHERE ID = %d\", $id));")
        verdict = classify(body)
        self.assertEqual(verdict.code, "C")
        self.assertNotIn("injection", verdict.why)

    def test_upload_allowlist_turns_a_write_into_a_drain(self):
        without = "move_uploaded_file($_FILES['f']['tmp_name'], $dir . $_FILES['f']['name']);"
        with_list = ("$allowed_types = array('png');"
                     "if (!in_array($ext, $allowed_types)) return;" + without)
        self.assertEqual(classify(without).code, "I")
        self.assertEqual(classify(with_list).code, "A")

    def test_empty_input_is_not_a_verdict(self):
        self.assertEqual(classify("").code, "-")
        self.assertEqual(classify("   \n\t ").code, "-")


class Contract(unittest.TestCase):
    """What callers and the README are allowed to rely on."""

    def test_verdict_unpacks_as_a_pair(self):
        code, why = classify("unlink($_GET['p']);")
        self.assertEqual(code, "I")
        self.assertTrue(why)

    def test_every_code_has_a_meaning_and_one_bucket(self):
        for code in MEANING:
            buckets = [code in IN_SCOPE, code in OUT_OF_SCOPE]
            self.assertLessEqual(sum(buckets), 1, "%s is in two buckets" % code)
        self.assertEqual(IN_SCOPE & OUT_OF_SCOPE, frozenset())

    def test_classify_never_raises_on_odd_input(self):
        for body in ("function f( {", "}" * 50, "/*" + "x" * 5000,
                     "<?php $a = '", "\x00\x01binary"):
            self.assertIn(classify(body).code, MEANING)


class Cli(unittest.TestCase):
    """The exit code is the product, so it is tested like one."""

    def _main(self, argv):
        out, err = io.StringIO(), io.StringIO()
        keep = sys.stdout, sys.stderr
        sys.stdout, sys.stderr = out, err
        try:
            code = main(argv)
        finally:
            sys.stdout, sys.stderr = keep
        return code, out.getvalue(), err.getvalue()

    def test_in_scope_file_exits_zero(self):
        code, out, _ = self._main(["file", str(FIXTURES / "in_scope.php"), "--no-colour"])
        self.assertEqual(code, EXIT_IN_SCOPE)
        self.assertIn("want_I_arbitrary_file_write", out)

    def test_out_of_scope_file_exits_one(self):
        code, _, _ = self._main(
            ["file", str(FIXTURES / "out_of_scope.php"), "--no-colour"])
        self.assertEqual(code, EXIT_OUT_OF_SCOPE)

    def test_undecided_file_exits_three(self):
        code, _, _ = self._main(
            ["file", str(FIXTURES / "undecided.php"), "--no-colour"])
        self.assertEqual(code, EXIT_UNDECIDED)

    def test_missing_path_exits_two(self):
        code, _, err = self._main(["file", str(FIXTURES / "nope.php")])
        self.assertEqual(code, EXIT_ERROR)
        self.assertIn("not a file", err)

    def test_scan_walks_a_tree(self):
        code, out, _ = self._main(["scan", str(PLUGIN), "--no-colour"])
        self.assertEqual(code, EXIT_IN_SCOPE)
        self.assertIn("handlers.php", out)

    def test_json_output_is_valid_json(self):
        import json
        _, out, _ = self._main(["file", str(FIXTURES / "in_scope.php"), "--json"])
        rows = json.loads(out)
        self.assertTrue(rows)
        self.assertEqual(sorted(rows[0]),
                         ["function", "meaning", "verdict", "where", "why"])

    def test_only_filter_narrows_the_output(self):
        _, out, _ = self._main(
            ["file", str(FIXTURES / "in_scope.php"), "--only", "C", "--no-colour"])
        self.assertIn("want_C_sqli_interpolation", out)
        self.assertNotIn("want_I_arbitrary_file_write", out)

    def test_verdicts_command_documents_every_code(self):
        _, out, _ = self._main(["verdicts"])
        for code in MEANING:
            self.assertIn(MEANING[code], out)


if __name__ == "__main__":
    unittest.main(verbosity=2)
