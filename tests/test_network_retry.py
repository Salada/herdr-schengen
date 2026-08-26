"""Unit tests for Network/API Error Adaptive Retry and Timeout handling (TODO #6)."""

import io
import json
import socket
import unittest
import urllib.error
from email.message import Message
from unittest.mock import MagicMock, patch

from core.cloud_judge import (
    MAX_ADAPTIVE_RETRIES,
    post_cloud_judge,
)


class TestCloudJudgeAdaptiveRetry(unittest.TestCase):
    """Test adaptive retry on transient network errors and rate limits."""

    @patch("time.sleep")
    @patch("urllib.request.urlopen")
    def test_post_cloud_judge_retry_on_429_success(self, mock_urlopen, mock_sleep):
        """Test HTTP 429 rate limit triggers adaptive retry and succeeds on 3rd attempt."""
        # 1st: 429, 2nd: 429, 3rd: 200 OK
        resp_429 = urllib.error.HTTPError(
            url="http://dummy", code=429, msg="Too Many Requests", hdrs=Message(), fp=io.BytesIO(b"{}")
        )
        mock_success = MagicMock()
        mock_success.__enter__.return_value = io.BytesIO(b'{"is_safe": true, "reason": "OK"}')

        mock_urlopen.side_effect = [resp_429, resp_429, mock_success]

        res = post_cloud_judge(
            messages=[{"role": "user", "content": "test"}],
            endpoint="http://dummy",
            model="dummy",
            api_key="sk-test",
            reasoning_effort="low",
            max_retries=10,
        )

        self.assertEqual(res, {"is_safe": True, "reason": "OK"})
        self.assertEqual(mock_urlopen.call_count, 3)
        self.assertEqual(mock_sleep.call_count, 2)

    @patch("time.sleep")
    @patch("urllib.request.urlopen")
    def test_post_cloud_judge_retry_on_502_503(self, mock_urlopen, mock_sleep):
        """Test HTTP 502/503 bad gateway errors trigger retry and succeed."""
        resp_502 = urllib.error.HTTPError(
            url="http://dummy", code=502, msg="Bad Gateway", hdrs=Message(), fp=io.BytesIO(b"{}")
        )
        resp_503 = urllib.error.HTTPError(
            url="http://dummy", code=503, msg="Service Unavailable", hdrs=Message(), fp=io.BytesIO(b"{}")
        )
        mock_success = MagicMock()
        mock_success.__enter__.return_value = io.BytesIO(b'{"is_safe": true, "reason": "Gateway recovered"}')

        mock_urlopen.side_effect = [resp_502, resp_503, mock_success]

        res = post_cloud_judge(
            messages=[{"role": "user", "content": "test"}],
            endpoint="http://dummy",
            model="dummy",
            api_key="sk-test",
            reasoning_effort="low",
            max_retries=10,
        )

        self.assertEqual(res, {"is_safe": True, "reason": "Gateway recovered"})
        self.assertEqual(mock_urlopen.call_count, 3)

    @patch("time.sleep")
    @patch("urllib.request.urlopen")
    def test_post_cloud_judge_retry_on_socket_timeout(self, mock_urlopen, mock_sleep):
        """Test socket timeout / TCP ACK timeout triggers adaptive retry."""
        timeout_err = socket.timeout("timed out")
        url_err = urllib.error.URLError("Connection reset by peer")
        mock_success = MagicMock()
        mock_success.__enter__.return_value = io.BytesIO(b'{"is_safe": true, "reason": "Recovered"}')

        mock_urlopen.side_effect = [timeout_err, url_err, mock_success]

        res = post_cloud_judge(
            messages=[{"role": "user", "content": "test"}],
            endpoint="http://dummy",
            model="dummy",
            api_key="sk-test",
            reasoning_effort="low",
            max_retries=10,
        )

        self.assertEqual(res, {"is_safe": True, "reason": "Recovered"})
        self.assertEqual(mock_urlopen.call_count, 3)

    @patch("time.sleep")
    @patch("urllib.request.urlopen")
    def test_post_cloud_judge_max_10_retries_exhausted(self, mock_urlopen, mock_sleep):
        """Test exhausting all 10 retry attempts raises exception."""
        resp_500 = urllib.error.HTTPError(
            url="http://dummy", code=500, msg="Internal Server Error", hdrs=Message(), fp=io.BytesIO(b"{}")
        )
        mock_urlopen.side_effect = [resp_500] * 10

        with self.assertRaises(urllib.error.HTTPError):
            post_cloud_judge(
                messages=[{"role": "user", "content": "test"}],
                endpoint="http://dummy",
                model="dummy",
                api_key="sk-test",
                reasoning_effort="low",
                max_retries=10,
            )

        self.assertEqual(mock_urlopen.call_count, 10)
        self.assertEqual(mock_sleep.call_count, 9)

    @patch("time.sleep")
    @patch("urllib.request.urlopen")
    def test_non_retryable_error_fails_immediately(self, mock_urlopen, mock_sleep):
        """Test non-retryable errors (e.g. 400 Bad Request) fail immediately without retry."""
        resp_400 = urllib.error.HTTPError(
            url="http://dummy", code=400, msg="Bad Request", hdrs=Message(), fp=io.BytesIO(b"{}")
        )
        mock_urlopen.side_effect = resp_400

        with self.assertRaises(urllib.error.HTTPError):
            post_cloud_judge(
                messages=[{"role": "user", "content": "test"}],
                endpoint="http://dummy",
                model="dummy",
                api_key="sk-test",
                reasoning_effort="low",
                max_retries=10,
            )

        self.assertEqual(mock_urlopen.call_count, 1)
        self.assertEqual(mock_sleep.call_count, 0)


if __name__ == "__main__":
    unittest.main()
