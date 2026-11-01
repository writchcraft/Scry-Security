"""Read a bounded forward snapshot with the modern Windows Event Log API."""

import importlib

from defusedxml import ElementTree
from defusedxml.common import DefusedXmlException

from scry_security.collectors.base import CollectionBatch, SourceStatus
from scry_security.parsers.windows_parser import parse_windows_xml

CHANNELS = {
    "Security",
    "System",
    "Application",
    "Microsoft-Windows-PowerShell/Operational",
    "Microsoft-Windows-Windows Defender/Operational",
}


def read_event_log(
    channel: str = "Security",
    *,
    after_record_id: int = 0,
    max_records: int = 1000,
) -> CollectionBatch:
    """Read records after a caller checkpoint; never change audit policy or clear logs.

    Record IDs are channel-local and can reset when logs are cleared. Callers
    must reconcile checkpoints against log health and clearing events.
    """
    if channel not in CHANNELS:
        raise ValueError("Unsupported Event Log channel")
    if not 0 <= after_record_id < 2**64 or not 1 <= max_records <= 10_000:
        raise ValueError("Invalid Event Log cursor or record limit")
    try:
        api = importlib.import_module("win32evtlog")
    except ImportError:
        return CollectionBatch((), SourceStatus.UNAVAILABLE, "Install the Windows dependency extra")
    query = None
    results = []
    cursor = after_record_id
    try:
        query = api.EvtQuery(
            channel,
            api.EvtQueryChannelPath | api.EvtQueryForwardDirection,
            f"*[System[EventRecordID > {after_record_id}]]",
        )
        while len(results) < max_records:
            try:
                handles = api.EvtNext(query, min(64, max_records - len(results)), 1000, 0)
            except (OSError, api.error) as exc:
                if getattr(exc, "winerror", None) == 259:  # ERROR_NO_MORE_ITEMS
                    break
                raise
            if not handles:
                break
            try:
                for handle in handles:
                    xml = api.EvtRender(handle, api.EvtRenderEventXml)
                    result = parse_windows_xml(xml)
                    results.append(result)
                    # Read the record ID even for unsupported event types, to
                    # avoid polling the same skipped records indefinitely.
                    if len(xml.encode("utf-8")) <= 262_144:
                        try:
                            root = ElementTree.fromstring(xml, forbid_dtd=True)
                            record_id = root.findtext(
                                "{http://schemas.microsoft.com/win/2004/08/events/event}System/"
                                "{http://schemas.microsoft.com/win/2004/08/events/event}EventRecordID"
                            )
                            if record_id is not None:
                                cursor = max(cursor, int(record_id))
                        except (ElementTree.ParseError, DefusedXmlException, ValueError):
                            # Parser reports malformed evidence; leave the cursor unchanged.
                            pass
            finally:
                for handle in handles:
                    handle.Close()
    except (OSError, api.error) as exc:
        status = (
            SourceStatus.PERMISSION_DENIED
            if getattr(exc, "winerror", None) == 5
            else SourceStatus.DEGRADED
        )
        return CollectionBatch(tuple(results), status, "Event Log query failed", str(cursor))
    except (ValueError, TypeError):
        return CollectionBatch(
            tuple(results), SourceStatus.DEGRADED, "Invalid native event response", str(cursor)
        )
    finally:
        if query is not None:
            query.Close()
    degraded = any(item.error for item in results)
    return CollectionBatch(
        tuple(results),
        SourceStatus.DEGRADED if degraded else SourceStatus.AVAILABLE,
        "Event Log snapshot complete; audit policy not verified",
        str(cursor),
    )
