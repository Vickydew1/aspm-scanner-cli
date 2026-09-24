"""GitHub PR provider - talks to the GitHub REST API with `requests`
(already a dependency here, see utils/common.py) instead of PR-Decorator's
original urllib, to match this codebase's conventions."""
import requests

from aspm_cli.utils.logger import Logger
from ..render import FINDING_MARKER_RE
from .base import PRProvider

API_ROOT = "https://api.github.com"
_TIMEOUT = 30


class GitHubProvider(PRProvider):
    def _headers(self):
        return {"Authorization": f"Bearer {self.token}", "Accept": "application/vnd.github+json"}

    def _get_all_pages(self, url):
        """GET a paginated GitHub list endpoint in full - default page size
        caps at 30, real PRs blow past that fast."""
        items = []
        page = 1
        while True:
            sep = "&" if "?" in url else "?"
            resp = requests.get(f"{url}{sep}per_page=100&page={page}", headers=self._headers(), timeout=_TIMEOUT)
            resp.raise_for_status()
            batch = resp.json()
            items.extend(batch)
            if len(batch) < 100:
                return items
            page += 1

    def _find_existing_summary_comment(self):
        comments = self._get_all_pages(f"{API_ROOT}/repos/{self.repo}/issues/{self.pr_id}/comments")
        for c in comments:
            if "accuknox-pr-decorator:summary" in c.get("body", ""):
                return c["id"]
        return None

    def find_posted_fingerprints(self):
        comments = self._get_all_pages(f"{API_ROOT}/repos/{self.repo}/pulls/{self.pr_id}/comments")
        fps = set()
        for c in comments:
            m = FINDING_MARKER_RE.search(c.get("body", ""))
            if m:
                fps.add(m.group(1))
        return fps

    def post_or_update_summary(self, body, dry_run):
        logger = Logger.get_logger()
        existing_id = None if dry_run else self._find_existing_summary_comment()
        if existing_id:
            url = f"{API_ROOT}/repos/{self.repo}/issues/comments/{existing_id}"
            method = "PATCH"
        else:
            url = f"{API_ROOT}/repos/{self.repo}/issues/{self.pr_id}/comments"
            method = "POST"

        if dry_run:
            logger.info(f"[DRY RUN] {method} {url}")
            return

        resp = requests.request(method, url, json={"body": body}, headers=self._headers(), timeout=_TIMEOUT)
        resp.raise_for_status()
        logger.info(f"Summary comment {'updated' if existing_id else 'created'}: {resp.status_code}")

    def post_review(self, body, event, comments, dry_run):
        logger = Logger.get_logger()
        url = f"{API_ROOT}/repos/{self.repo}/pulls/{self.pr_id}/reviews"
        payload = {"commit_id": self.head_sha, "body": body, "event": event, "comments": comments}

        if dry_run:
            logger.info(f"[DRY RUN] POST {url} ({len(comments)} inline comment(s), event={event})")
            return

        resp = requests.post(url, json=payload, headers=self._headers(), timeout=_TIMEOUT)
        resp.raise_for_status()
        logger.info(f"Review posted: {resp.status_code}")
