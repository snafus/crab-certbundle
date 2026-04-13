"""Tests for certbundle.reporting — diff and inventory rendering."""

import json
import pytest

from certbundle.cert import parse_pem_data
from certbundle.reporting import (
    diff_cert_sets,
    render_diff_text,
    render_diff_json,
    render_inventory,
    CertDiff,
)


class TestDiffCertSets:
    def test_no_change(self, ca_pem):
        certs = parse_pem_data(ca_pem)
        d = diff_cert_sets(certs, certs)
        assert d.added == []
        assert d.removed == []
        assert len(d.unchanged) == 1
        assert not d.has_changes

    def test_added(self, ca_pem, second_ca_pem):
        old = parse_pem_data(ca_pem)
        new = parse_pem_data(ca_pem) + parse_pem_data(second_ca_pem)
        d = diff_cert_sets(old, new)
        assert len(d.added) == 1
        assert d.added[0].subject == parse_pem_data(second_ca_pem)[0].subject

    def test_removed(self, ca_pem, second_ca_pem):
        old = parse_pem_data(ca_pem) + parse_pem_data(second_ca_pem)
        new = parse_pem_data(ca_pem)
        d = diff_cert_sets(old, new)
        assert len(d.removed) == 1

    def test_empty_old(self, ca_pem):
        d = diff_cert_sets([], parse_pem_data(ca_pem))
        assert len(d.added) == 1
        assert d.has_changes

    def test_empty_new(self, ca_pem):
        d = diff_cert_sets(parse_pem_data(ca_pem), [])
        assert len(d.removed) == 1
        assert d.has_changes

    def test_both_empty(self):
        d = diff_cert_sets([], [])
        assert not d.has_changes


class TestRenderDiffText:
    def test_no_changes(self, ca_pem):
        certs = parse_pem_data(ca_pem)
        d = diff_cert_sets(certs, certs)
        text = render_diff_text(d)
        assert "ADDED" not in text or "+0" in text or "0 added" in text.lower() or "+0" in text

    def test_added_section(self, ca_pem, second_ca_pem):
        old = parse_pem_data(ca_pem)
        new = parse_pem_data(ca_pem) + parse_pem_data(second_ca_pem)
        d = diff_cert_sets(old, new)
        text = render_diff_text(d)
        assert "ADDED" in text

    def test_removed_section(self, ca_pem, second_ca_pem):
        old = parse_pem_data(ca_pem) + parse_pem_data(second_ca_pem)
        new = parse_pem_data(ca_pem)
        d = diff_cert_sets(old, new)
        text = render_diff_text(d)
        assert "REMOVED" in text


class TestRenderDiffJson:
    def test_valid_json(self, ca_pem, second_ca_pem):
        old = parse_pem_data(ca_pem)
        new = parse_pem_data(ca_pem) + parse_pem_data(second_ca_pem)
        d = diff_cert_sets(old, new)
        text = render_diff_json(d)
        data = json.loads(text)
        assert "summary" in data
        assert "added" in data
        assert data["summary"]["added"] == 1

    def test_summary_keys(self, ca_pem):
        d = diff_cert_sets([], parse_pem_data(ca_pem))
        data = json.loads(render_diff_json(d))
        assert set(data["summary"].keys()) == {"added", "removed", "changed", "unchanged"}


class TestRenderInventory:
    def test_text_format(self, ca_pem, second_ca_pem):
        certs = parse_pem_data(ca_pem) + parse_pem_data(second_ca_pem)
        text = render_inventory(certs)
        assert "Test CA" in text

    def test_json_format(self, ca_pem):
        certs = parse_pem_data(ca_pem)
        data = json.loads(render_inventory(certs, format="json"))
        assert isinstance(data, list)
        assert len(data) == 1
        assert "subject" in data[0]
        assert "fingerprint_sha256" in data[0]

    def test_empty_list(self):
        text = render_inventory([])
        assert isinstance(text, str)
