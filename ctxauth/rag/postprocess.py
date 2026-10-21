"""К11: постобработка ответа. Внешние ссылки/изображения на домены вне разрешительного списка
не рендерятся и журналируются (решение из модели угроз: «заблокирован и логируется»)."""
from __future__ import annotations

from dataclasses import dataclass, field

from ..text import MD_IMAGE_RE, URL_RE, domain_allowed, url_domain


@dataclass
class PostprocessResult:
    text: str
    blocked_urls: list[str] = field(default_factory=list)


def postprocess(text: str, allowlist: frozenset[str]) -> PostprocessResult:
    blocked: list[str] = []

    def img(m):
        url = m.group(1)
        if domain_allowed(url_domain(url), allowlist):
            return m.group(0)
        blocked.append(url)
        return "[image removed]"

    text = MD_IMAGE_RE.sub(img, text)

    def link(m):
        url = m.group(0)
        if domain_allowed(url_domain(url), allowlist):
            return url
        blocked.append(url)
        return "[link removed]"

    text = URL_RE.sub(link, text)
    return PostprocessResult(text, blocked)
