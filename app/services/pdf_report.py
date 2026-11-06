"""
pdf_report.py - builds the downloadable PDF report with fpdf2.

Sections (same honesty labels as the alerts):
  1. Observed facts       - measured directly (bytes, domains, ports, "observed" alerts)
  2. Inferred             - conclusions drawn from observed facts
  3. Potential risks      - things that COULD matter, not proven
  4. Cannot be observed   - limits of metadata monitoring
  5. AI explanation       - Gemini text (or the rule-based fallback), clearly labelled
"""
import os
import re
from datetime import datetime, timezone

from fpdf import FPDF
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app import config, models
from app.services.analytics import build_summary
from app.services.insights import NOT_OBSERVABLE, get_or_create_insight

DISCLAIMER = ("This report describes network METADATA only (destinations, ports, byte counts, timing). "
              "Encrypted contents were not read. Findings describe unusual behavior worth reviewing, "
              "not proof of wrongdoing.")

# fpdf2's built-in fonts only know Latin-1 characters; swap common "fancy" ones for plain ones.
_REPLACEMENTS = {"‘": "'", "’": "'", "“": '"', "”": '"', "–": "-", "—": "-",
                 "•": "-", "…": "...", "≈": "~", "→": "->", " ": " "}


def _t(text) -> str:
    """Make any text safe for the PDF font, and strip simple markdown from Gemini output."""
    s = str(text if text is not None else "")
    for bad, good in _REPLACEMENTS.items():
        s = s.replace(bad, good)
    s = s.replace("**", "").replace("__", "")
    s = re.sub(r"^#{1,6}\s*", "", s, flags=re.MULTILINE)          # "## Heading" -> "Heading"
    s = re.sub(r"^\s*[*+]\s+", "- ", s, flags=re.MULTILINE)        # "* item" -> "- item"
    return s.encode("latin-1", "replace").decode("latin-1")


def _mb(n: int) -> str:
    return f"{n / 1_000_000:.2f} MB"


def _fmt_time(dt: datetime | None) -> str:
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC") if dt else "-"


class ReportPDF(FPDF):
    def footer(self):
        """fpdf2 calls this automatically at the bottom of every page."""
        self.set_y(-12)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(120)
        self.cell(0, 6, f"AppFlow Sentinel - metadata only, not proof of wrongdoing - page {self.page_no()}",
                  align="C")
        self.set_text_color(0)

    # small helpers so the build function reads like a document outline
    def h1(self, text):
        self.set_font("Helvetica", "B", 18)
        self.cell(0, 10, _t(text), new_x="LMARGIN", new_y="NEXT")

    def h2(self, text):
        self.ln(4)
        self.set_fill_color(230, 236, 245)
        self.set_font("Helvetica", "B", 13)
        self.cell(0, 8, _t(text), fill=True, new_x="LMARGIN", new_y="NEXT")
        self.ln(1)

    def para(self, text, size=10, style=""):
        self.set_font("Helvetica", style, size)
        self.multi_cell(0, 5, _t(text), new_x="LMARGIN", new_y="NEXT")

    def bullet(self, text):
        self.para(f"- {text}")

    def table_rows(self, header, rows, widths, align):
        self.set_font("Helvetica", "", 9)
        self.set_fill_color(255, 255, 255)  # tables are white even if a coloured banner came before
        with self.table(col_widths=widths, text_align=align, line_height=6) as table:
            for r in [header, *rows]:
                row = table.row()
                for value in r:
                    row.cell(_t(value))


def _alert_block(pdf: ReportPDF, a: models.SecurityAlert):
    pdf.para(f"[{a.severity.upper()}] {a.title}", style="B")
    pdf.para(a.description, size=9)
    if a.evidence:
        pdf.para("Evidence: " + ", ".join(f"{k}={v}" for k, v in a.evidence.items()), size=8, style="I")
    pdf.ln(1)


def build_report_pdf(db: Session, session: models.MonitoringSession, path: str) -> None:
    summary = build_summary(db, session)
    alerts = list(db.scalars(select(models.SecurityAlert).where(models.SecurityAlert.session_id == session.id)
                             .order_by(models.SecurityAlert.detected_at, models.SecurityAlert.id)))
    by_type = {k: [a for a in alerts if a.evidence_type == k]
               for k in ("observed", "inferred", "potential_risk", "not_observable")}
    C = models.NetworkConnection
    ports = list(db.execute(select(C.port, C.protocol, func.count(C.id)).where(C.session_id == session.id)
                            .group_by(C.port, C.protocol).order_by(func.count(C.id).desc()).limit(10)))
    # Re-uses the cache: no new Gemini call if the evidence hasn't changed.
    insight, _ = get_or_create_insight(db, session)

    pdf = ReportPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    pdf.h1("AppFlow Sentinel - Network Metadata Report")

    if session.is_mock:
        pdf.set_fill_color(255, 225, 225)
        pdf.set_font("Helvetica", "B", 11)
        pdf.cell(0, 8, "SIMULATED TEST DATA (is_mock = true) - not from a real device",
                 fill=True, align="C", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(2)

    pdf.table_rows(["Field", "Value"], [
        ["App", f"{summary.app.app_name or '-'} ({summary.app.package_name})"],
        ["Session ID", f"{session.id} ({summary.status.value})"],
        ["Started / Stopped", f"{_fmt_time(summary.started_at)}  /  {_fmt_time(summary.stopped_at)}"],
        ["Duration", f"{summary.duration_seconds} s"],
        ["Risk score (from analysis engine)",
         f"{summary.risk_score if summary.risk_score is not None else '-'}"
         f" ({summary.risk_level.value if summary.risk_level else 'n/a'})"],
        ["Report generated", _fmt_time(datetime.now(timezone.utc))],
    ], widths=(55, 125), align=("LEFT", "LEFT"))
    pdf.ln(2)
    pdf.para(DISCLAIMER, size=9, style="I")

    # 1. Observed facts ------------------------------------------------------
    pdf.h2("1. Observed facts")
    pdf.bullet(f"Uploaded: {_mb(summary.total_bytes_up)}   Downloaded: {_mb(summary.total_bytes_down)}")
    pdf.bullet(f"Connections: {summary.total_connections}   Unique domains: {summary.unique_domains}")
    pdf.bullet(f"Alerts: {summary.alert_counts.high} high, {summary.alert_counts.medium} medium, "
               f"{summary.alert_counts.low} low")
    sources = dict(db.execute(select(func.coalesce(C.domain_source, "not reported"), func.count(C.id))
                              .where(C.session_id == session.id).group_by(C.domain_source)).all())
    if sources:
        pdf.bullet("How domain names were known: " + ", ".join(
            f"{name} {count}" for name, count in sorted(sources.items())) +
            "  (dns = DNS reply, sni = TLS handshake name, unavailable = not observable)")
    if summary.top_domains:
        pdf.ln(2)
        pdf.para("Top destinations", style="B")
        pdf.table_rows(["Domain / IP", "Upload", "Download", "Conns"],
                       [[d.domain, _mb(d.bytes_up), _mb(d.bytes_down), str(d.connection_count)]
                        for d in summary.top_domains],
                       widths=(85, 35, 35, 25), align=("LEFT", "RIGHT", "RIGHT", "RIGHT"))
    if ports:
        pdf.ln(2)
        pdf.para("Ports used", style="B")
        pdf.table_rows(["Port", "Protocol", "Connections"], [[str(p), proto, str(n)] for p, proto, n in ports],
                       widths=(40, 40, 40), align=("LEFT", "LEFT", "RIGHT"))
    if by_type["observed"]:
        pdf.ln(2)
        pdf.para("Alerts based on observed evidence", style="B")
        for a in by_type["observed"]:
            _alert_block(pdf, a)

    # 2-3. Inferred / potential ---------------------------------------------
    for title, key, empty in (("2. Inferred", "inferred", "No inferred findings."),
                              ("3. Potential risks", "potential_risk", "No potential risks were flagged.")):
        pdf.h2(title)
        if by_type[key]:
            for a in by_type[key]:
                _alert_block(pdf, a)
        else:
            pdf.para(empty)

    # 4. Cannot be observed --------------------------------------------------
    pdf.h2("4. Cannot be observed")
    for item in NOT_OBSERVABLE:
        pdf.bullet(item)
    for a in by_type["not_observable"]:
        _alert_block(pdf, a)

    # 5. AI explanation ------------------------------------------------------
    pdf.h2("5. AI explanation")
    label = (f"Generated by Gemini ({insight.model}) from sanitized metadata only."
             if insight.source == "gemini" else "Gemini was unavailable - rule-based summary shown instead.")
    pdf.para(label, size=9, style="I")
    pdf.ln(1)
    pdf.para(insight.text)

    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    pdf.output(path)


def create_report(db: Session, session: models.MonitoringSession) -> models.Report:
    """Build the PDF file and save a row pointing to it."""
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_%f")
    filename = f"appflow_session_{session.id}_{stamp}.pdf"
    path = os.path.abspath(os.path.join(config.REPORTS_DIR, filename))
    build_report_pdf(db, session, path)
    row = models.Report(session_id=session.id, filename=filename, file_path=path, is_mock=session.is_mock)
    db.add(row)
    db.commit()
    return row
