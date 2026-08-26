#!/usr/bin/env python3
"""Unit tests for Feature Requests Backlog, FTS5 CJK Trigram search, and non-blocking TUI queueing.

Verifies:
1. Independent SQLite storage and schema creation (feature_requests.db).
2. FTS5 Trigram tokenizer precision for Korean/CJK n-gram similarity search.
3. Automatic database triggers (AFTER INSERT, AFTER UPDATE, AFTER DELETE) syncing FTS virtual table.
4. Autonomous agent tools: `create_feature_request` and `search_feature_requests`.
5. Non-blocking TUI /feature-request command execution during active agent investigation.
6. Self-improvement task lifecycle: PENDING -> IN_PROGRESS -> RESOLVED / REJECTED.
"""

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from core.feature_db import (
    add_feature_request,
    get_feature_request_by_id,
    list_feature_requests,
    pull_next_feature_request,
    search_similar_feature_requests,
    update_feature_request_status,
)
from tools.schengen_agent_llm import execute_tool_call

try:
    from cmd.schengen_tui import SchengenTUIApp
    HAS_TEXTUAL = True
except ImportError:
    SchengenTUIApp = None  # type: ignore
    HAS_TEXTUAL = False


class TestFeatureRequestsDB(unittest.TestCase):
    """Test independent SQLite feature requests database and FTS5 CJK trigram search."""

    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmp_dir.name) / "test_feature_requests.db"

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_crud_and_lifecycle(self):
        # 1. Add feature requests
        id1 = add_feature_request(
            title="TUI 다크 모드 테마 지원",
            description="monokai 기반 다크 모드 토글 기능 추가",
            priority="HIGH",
            category="UI",
            db_path=self.db_path,
        )
        id2 = add_feature_request(
            title="Schengen FTS5 CJK 전문검색 구축",
            description="한국어 형태소 및 n-gram trigram 유사도 검색 지원",
            priority="CRITICAL",
            category="SEARCH",
            db_path=self.db_path,
        )
        self.assertEqual(id1, 1)
        self.assertEqual(id2, 2)

        # 2. Get by ID
        req1 = get_feature_request_by_id(id1, db_path=self.db_path)
        self.assertIsNotNone(req1)
        assert req1 is not None
        self.assertEqual(req1["title"], "TUI 다크 모드 테마 지원")
        self.assertEqual(req1["priority"], "HIGH")
        self.assertEqual(req1["status"], "PENDING")

        # 3. List
        all_reqs = list_feature_requests(db_path=self.db_path)
        self.assertEqual(len(all_reqs), 2)

        # 4. Pull next task (FIFO)
        claimed = pull_next_feature_request(worker_name="bot-agy-macmini", db_path=self.db_path)
        self.assertIsNotNone(claimed)
        assert claimed is not None
        self.assertEqual(claimed["id"], id1)
        self.assertEqual(claimed["status"], "IN_PROGRESS")
        self.assertEqual(claimed["assigned_to"], "bot-agy-macmini")

        # 5. Resolve task
        ok = update_feature_request_status(id1, "RESOLVED", resolution_note="PR #62 merged", db_path=self.db_path)
        self.assertTrue(ok)
        resolved = get_feature_request_by_id(id1, db_path=self.db_path)
        assert resolved is not None
        self.assertEqual(resolved["status"], "RESOLVED")
        self.assertEqual(resolved["resolution_note"], "PR #62 merged")
        self.assertIsNotNone(resolved["resolved_at"])

    def test_fts5_cjk_trigram_similarity_search_and_triggers(self):
        # Insert test items with Korean words
        add_feature_request(title="마크다운 테이블 렌더링 최적화", description="GFM 표 가로폭 자동 정렬", db_path=self.db_path)
        add_feature_request(title="신택스 하이라이팅 지원", description="monokai python json 코드 블록", db_path=self.db_path)
        add_feature_request(title="도구 호출 로그 마크다운 포맷팅", description="백틱 및 JSON 코드 블록 서식화", db_path=self.db_path)

        # Search exact & partial Korean keywords
        res1 = search_similar_feature_requests("마크다운", db_path=self.db_path)
        self.assertEqual(len(res1), 2)
        titles = [r["title"] for r in res1]
        self.assertIn("마크다운 테이블 렌더링 최적화", titles)
        self.assertIn("도구 호출 로그 마크다운 포맷팅", titles)

        # Search description keyword
        res2 = search_similar_feature_requests("코드 블록", db_path=self.db_path)
        self.assertEqual(len(res2), 2)

        # Verify UPDATE trigger updates FTS5
        req = search_similar_feature_requests("최적화", db_path=self.db_path)[0]
        update_feature_request_status(req["id"], "RESOLVED", resolution_note="Done", db_path=self.db_path)
        res_resolved = search_similar_feature_requests("최적화", status="RESOLVED", db_path=self.db_path)
        self.assertEqual(len(res_resolved), 1)

    def test_fts5_sub3_char_cjk_fallback(self):
        # 2-char Korean words (sub-3-chars where pure trigram cannot construct 3-gram tokens)
        add_feature_request(title="다크 모드 테마 지원", description="monokai 기반", db_path=self.db_path)
        add_feature_request(title="마크다운 테이블 렌더링 최적화", description="GFM 표", db_path=self.db_path)

        # 2-char query "모드"
        res_mode = search_similar_feature_requests("모드", db_path=self.db_path)
        self.assertGreaterEqual(len(res_mode), 1)
        self.assertEqual(res_mode[0]["title"], "다크 모드 테마 지원")

        # 1-char query "표"
        res_table = search_similar_feature_requests("표", db_path=self.db_path)
        self.assertGreaterEqual(len(res_table), 1)
        self.assertEqual(res_table[0]["title"], "마크다운 테이블 렌더링 최적화")

    def test_concurrent_fifo_pull_race_defense(self):
        import threading
        # Seed 1 single pending item
        add_feature_request(title="단일 태스크", db_path=self.db_path)

        claimed_workers = []
        def try_pull(worker_id):
            res = pull_next_feature_request(worker_name=worker_id, db_path=self.db_path)
            if res:
                claimed_workers.append(worker_id)

        threads = [threading.Thread(target=try_pull, args=(f"worker-{i}",)) for i in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Exactly 1 worker must have claimed the single pending task
        self.assertEqual(len(claimed_workers), 1)

    def test_create_feature_request_with_similars_dry(self):
        from core.feature_db import create_feature_request_with_similars
        # Add initial item
        create_feature_request_with_similars(title="TUI 알림음 설정", description="볼륨 조절", db_path=self.db_path)
        # Add similar item
        created = create_feature_request_with_similars(title="TUI 알림음 커스텀", description="사운드 파일 선택", db_path=self.db_path)
        self.assertIn("id", created)
        self.assertEqual(created["title"], "TUI 알림음 커스텀")
        self.assertEqual(len(created["similar_items"]), 1)
        self.assertEqual(created["similar_items"][0]["title"], "TUI 알림음 설정")


class TestAgentLLMFeatureTools(unittest.TestCase):
    """Test LLM Agent tool execution for feature requests."""

    def test_create_and_search_feature_tool(self):
        import json
        create_res = execute_tool_call(
            "create_feature_request",
            {
                "title": "TUI 자동 스크롤 개선",
                "description": "새 메시지 추가 시 하단 스크롤 위치 유지",
                "priority": "HIGH",
                "category": "UI",
            },
        )
        data = json.loads(create_res)
        self.assertEqual(data.get("status"), "created")
        self.assertIn("id", data)
        self.assertEqual(data.get("title"), "TUI 자동 스크롤 개선")

        # Search via tool
        search_res = execute_tool_call(
            "search_feature_requests",
            {"query": "스크롤", "limit": 5},
        )
        search_data = json.loads(search_res)
        self.assertGreaterEqual(search_data.get("count", 0), 1)


@unittest.skipUnless(HAS_TEXTUAL, "Textual is required for TUI tests")
class TestTUINonBlockingFeatureQueueing(unittest.TestCase):
    """Test that /feature-request queues immediately even when agent investigation is in-flight."""

    def setUp(self):
        import asyncio
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)

    def tearDown(self):
        import asyncio
        if hasattr(self, "loop") and not self.loop.is_closed():
            self.loop.close()
        asyncio.set_event_loop(asyncio.new_event_loop())

    def test_feature_request_command_non_blocking_during_inflight_task(self):
        import asyncio
        async def run_test_async():
            assert SchengenTUIApp is not None
            app = SchengenTUIApp()
            async with app.run_test() as pilot:
                # Simulate active in-flight investigation
                app._processing_chat = True
                with patch("cmd.schengen_tui.create_feature_request_with_similars") as mock_create:
                    mock_create.return_value = {
                        "id": 42,
                        "title": "TUI 알림음 커스텀",
                        "description": "볼륨 조절 및 음소거 모드",
                        "priority": "HIGH",
                        "similar_items": [],
                    }
                    app.process_user_chat("/feature-request TUI 알림음 커스텀 --desc 볼륨 조절 및 음소거 모드 --priority HIGH")
                    await pilot.pause(0.1)

                    mock_create.assert_called_once()
                    call_kwargs = mock_create.call_args.kwargs
                    self.assertEqual(call_kwargs["title"], "TUI 알림음 커스텀")
                    self.assertEqual(call_kwargs["description"], "볼륨 조절 및 음소거 모드")
                    self.assertEqual(call_kwargs["priority"], "HIGH")

        self.loop.run_until_complete(run_test_async())


if __name__ == "__main__":
    unittest.main()
