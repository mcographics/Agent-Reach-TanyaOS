from types import SimpleNamespace
from unittest.mock import patch

import pytest


def test_fork_build_tag_does_not_prompt_upstream_downgrade():
    from agent_reach.cli import _is_newer_version
    assert not _is_newer_version("1.4.2", "1.5.0+tanya.1")
    assert not _is_newer_version("1.5.0", "1.5.0+tanya.1")
    assert _is_newer_version("1.6.0", "1.5.0+tanya.1")

from agent_reach import tanya


@pytest.mark.parametrize("url", ["http://127.0.0.1/", "http://localhost/", "http://169.254.169.254/", "file:///x", "https://user:password@example.com/"])
def test_nonpublic_and_credential_urls_never_resolve(url):
    with patch.object(tanya.socket, "getaddrinfo") as dns:
        with pytest.raises(ValueError):
            tanya.fetch_public(url)
        dns.assert_not_called()


def test_mixed_dns_public_and_private_addresses_are_rejected():
    records = [(None, None, None, None, (ip, 443)) for ip in ["93.184.216.34", "10.0.0.1"]]
    with patch.object(tanya.socket, "getaddrinfo", return_value=records):
        with pytest.raises(tanya.ReachError, match="Private"):
            tanya._resolve_public("public.example", 443)


class Connection:
    response = None
    calls = []
    def __init__(self, *args):
        self.calls.append(args)
    def request(self, *args, **kwargs): pass
    def getresponse(self): return self.response
    def close(self): pass


def response(body=b"hello", status=200, **headers):
    return SimpleNamespace(status=status, getheader=lambda key, default=None: headers.get(key, default),
                           read=lambda size: body[:size])


def test_redirect_to_private_host_is_blocked_before_second_request():
    Connection.response = response(status=302, Location="http://127.0.0.1/private")
    Connection.calls = []
    with patch.object(tanya, "_resolve_public", return_value="93.184.216.34"), patch.object(tanya, "_PinnedHTTPS", Connection):
        with pytest.raises(ValueError):
            tanya.fetch_public("https://example.com/")
    assert len(Connection.calls) == 1
    assert Connection.calls[0][1] == "93.184.216.34"


def test_oversize_response_is_rejected():
    Connection.response = response(**{"Content-Length": str(tanya.MAX_BYTES + 1)})
    with patch.object(tanya, "_resolve_public", return_value="93.184.216.34"), patch.object(tanya, "_PinnedHTTPS", Connection):
        with pytest.raises(tanya.ReachError, match="limit"):
            tanya.fetch_public("https://example.com/")


def test_web_content_has_provenance_and_does_not_run_scripts():
    body = b"<html><title>Public title</title><script>stealSecrets()</script><p>Public evidence</p></html>"
    with patch.object(tanya, "fetch_public", return_value=(body, "text/html", "https://example.com/")):
        result = tanya.read_web("https://example.com/")
    assert result["trust"] == "external_untrusted" and result["instruction_authority"] is False
    assert "Public evidence" in result["text"] and "stealSecrets" not in result["text"]


def test_rss_is_parsed_from_bounded_bytes_and_limit_is_enforced():
    body = b'<rss version="2.0"><channel><title>Feed</title><item><title>One</title><link>https://example.com/1</link></item><item><title>Two</title></item></channel></rss>'
    with patch.object(tanya, "fetch_public", return_value=(body, "application/xml", "https://example.com/feed")):
        result = tanya.read_rss("https://example.com/feed", 1)
    assert len(result["entries"]) == 1 and result["entries"][0]["title"] == "One"


def test_repository_input_cannot_change_public_api_route():
    with patch.object(tanya, "fetch_public") as fetch:
        with pytest.raises(tanya.ReachError):
            tanya.github_repo("owner/repo/../../user")
        fetch.assert_not_called()


def test_status_never_contacts_sites_or_reads_credential_config():
    with patch.object(tanya, "fetch_public") as fetch:
        result = tanya.status()
    fetch.assert_not_called()
    assert not result["credentials_used"] and not result["live_verified"]


def test_unknown_action_and_invalid_limits_fail_closed():
    with pytest.raises(tanya.ReachError):
        tanya.execute("install", {})
    for limit in [True, 0, 21, "5"]:
        with pytest.raises(tanya.ReachError):
            tanya._limit(limit)


def test_youtube_rejects_other_domains_before_extraction():
    with patch("yt_dlp.YoutubeDL") as extractor:
        with pytest.raises(tanya.ReachError):
            tanya.youtube("https://youtube.com.evil.example/video")
        extractor.assert_not_called()
