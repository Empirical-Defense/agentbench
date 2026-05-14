from __future__ import annotations

import csv
import hashlib
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Set, Tuple

AIUC_PATTERN = re.compile(r"^[A-Z]\d{3}(?:\.\d+)?$")
OWASP_PATTERN = re.compile(r"^LLM\d{2}(?:\.\d+)?$")
NIST_PATTERN = re.compile(r"^(GOVERN|MANAGE|MAP|MEASURE)\d+(?:\.\d+)?$")
NIST_HEADER_PATTERN = re.compile(r"^([A-Z]+)\s+(\d+(?:\.\d+)?)$")

OWASP_TO_NIST_FAMILY: Dict[str, str] = {
    "LLM01": "MAP",
    "LLM02": "MANAGE",
    "LLM03": "MAP",
    "LLM04": "MANAGE",
    "LLM05": "GOVERN",
    "LLM06": "GOVERN",
    "LLM07": "MANAGE",
    "LLM08": "MANAGE",
    "LLM09": "MEASURE",
    "LLM10": "GOVERN",
}


@dataclass
class OverlapInfo:
    framework_tags: List[str]
    overlap_control_ids: List[str]
    execution_group_id: str
    crosswalk_root_id: str


class OverlapIndex:
    """Cross-framework overlap index based on AIUC->OWASP mapping plus deterministic NIST rollup."""

    def __init__(self, root: Path | None = None) -> None:
        self.root = root or Path(__file__).resolve().parent.parent
        self.aiuc_to_owasp, self.owasp_to_aiuc = self._load_aiuc_owasp_crosswalk()
        self.nist_controls_by_family = self._load_nist_controls_by_family()

    def _load_nist_controls_by_family(self) -> Dict[str, Set[str]]:
        """Load concrete NIST control IDs grouped by family from the wide playbook CSV."""
        controls_by_family: Dict[str, Set[str]] = {}
        path = self.root / "data" / "nist_ai_rmf_playbook.csv"
        if not path.exists():
            return controls_by_family

        try:
            with path.open("r", encoding="utf-8-sig", newline="") as handle:
                rows = list(csv.reader(handle))
        except Exception:
            return controls_by_family

        if not rows:
            return controls_by_family

        headers = rows[0]
        for raw_header in headers[1:]:
            header = (raw_header or "").strip()
            if not header:
                continue
            match = NIST_HEADER_PATTERN.match(header)
            if not match:
                continue
            family, number = match.groups()
            control_id = f"{family}{number}"
            controls_by_family.setdefault(family, set()).add(control_id)

        return controls_by_family

    def _active_owasp_version_dir(self) -> str:
        active_path = self.root / "frameworks" / "crosswalks" / "active_versions.env"
        if not active_path.exists():
            return "1_1"

        version_value = ""
        for line in active_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            if key.strip() == "OWASP_LLM_TOP10_ACTIVE_VERSION":
                version_value = value.strip().strip('"').strip("'")
                break

        if not version_value:
            return "1_1"

        return version_value.replace(".", "_")

    def _crosswalk_path(self) -> Path:
        version_dir = self._active_owasp_version_dir()
        return (
            self.root
            / "frameworks"
            / "crosswalks"
            / "owasp_llm_top10"
            / version_dir
            / "aiuc_to_owasp_llm_top10.csv"
        )

    def _load_aiuc_owasp_crosswalk(self) -> Tuple[Dict[str, Set[str]], Dict[str, Set[str]]]:
        path = self._crosswalk_path()
        aiuc_to_owasp: Dict[str, Set[str]] = {}
        owasp_to_aiuc: Dict[str, Set[str]] = {}

        if not path.exists():
            return aiuc_to_owasp, owasp_to_aiuc

        with path.open("r", encoding="utf-8-sig", newline="") as handle:
            reader = csv.DictReader(handle)
            for row in reader:
                aiuc = (row.get("aiuc_control_id") or "").strip().upper()
                owasp = (row.get("owasp_llm_risk_id") or "").strip().upper()
                if not aiuc or not owasp:
                    continue
                aiuc_to_owasp.setdefault(aiuc, set()).add(owasp)
                owasp_to_aiuc.setdefault(owasp, set()).add(aiuc)

        return aiuc_to_owasp, owasp_to_aiuc

    @staticmethod
    def _base_aiuc(control_id: str) -> str:
        return control_id.split(".")[0].upper()

    @staticmethod
    def _base_owasp(control_id: str) -> str:
        return control_id.split(".")[0].upper()

    @staticmethod
    def _base_nist_family(control_id: str) -> str:
        match = re.match(r"^(GOVERN|MANAGE|MAP|MEASURE)", control_id.upper())
        return match.group(1) if match else ""

    def overlap_for(self, control_id: str) -> OverlapInfo:
        cid = (control_id or "").strip().upper()
        if not cid:
            return OverlapInfo(
                framework_tags=[],
                overlap_control_ids=[],
                execution_group_id="",
                crosswalk_root_id="",
            )

        origin = ""
        framework_tags: Set[str] = set()
        linked_ids: Set[str] = set()
        aiuc_ids: Set[str] = set()
        owasp_ids: Set[str] = set()
        nist_families: Set[str] = set()
        nist_control_ids: Set[str] = set()

        if AIUC_PATTERN.match(cid):
            origin = "AIUC"
            framework_tags.add("AIUC")
            aiuc_ids.add(self._base_aiuc(cid))
        elif OWASP_PATTERN.match(cid):
            origin = "OWASP"
            framework_tags.add("OWASP")
            owasp_ids.add(self._base_owasp(cid))
        elif NIST_PATTERN.match(cid):
            origin = "NIST"
            framework_tags.add("NIST")
            family = self._base_nist_family(cid)
            if family:
                nist_families.add(family)
            nist_control_ids.add(cid)

        for aiuc in list(aiuc_ids):
            mapped_owasp = self.aiuc_to_owasp.get(aiuc, set())
            owasp_ids.update(mapped_owasp)

        for owasp in list(owasp_ids):
            if origin != "AIUC":
                mapped_aiuc = self.owasp_to_aiuc.get(owasp, set())
                aiuc_ids.update(mapped_aiuc)
            nist_family = OWASP_TO_NIST_FAMILY.get(owasp)
            if nist_family:
                nist_families.add(nist_family)

        if nist_families and not owasp_ids:
            for owasp, nist_family in OWASP_TO_NIST_FAMILY.items():
                if nist_family in nist_families:
                    owasp_ids.add(owasp)
                    aiuc_ids.update(self.owasp_to_aiuc.get(owasp, set()))

        for family in nist_families:
            nist_control_ids.update(self.nist_controls_by_family.get(family, {family}))

        if aiuc_ids:
            framework_tags.add("AIUC")
            linked_ids.update(sorted(aiuc_ids))
        if owasp_ids:
            framework_tags.add("OWASP")
            linked_ids.update(sorted(owasp_ids))
        if nist_control_ids:
            framework_tags.add("NIST")
            linked_ids.update(sorted(nist_control_ids))

        group_parts_map: Dict[str, str] = {}
        if aiuc_ids:
            group_parts_map["AIUC"] = "AIUC:" + ",".join(sorted(aiuc_ids))
        if owasp_ids:
            group_parts_map["OWASP"] = "OWASP:" + ",".join(sorted(owasp_ids))
        if nist_control_ids:
            group_parts_map["NIST"] = "NIST:" + ",".join(sorted(nist_control_ids))

        ordered_frameworks = sorted(group_parts_map.keys())
        group_parts = [group_parts_map[framework] for framework in ordered_frameworks]
        execution_group_id = " | ".join(group_parts) if group_parts else cid
        canonical_seed = "||".join(group_parts) if group_parts else cid
        crosswalk_root_id = f"XW-{hashlib.sha1(canonical_seed.encode('utf-8')).hexdigest()[:12]}"

        return OverlapInfo(
            framework_tags=sorted(framework_tags),
            overlap_control_ids=sorted(linked_ids),
            execution_group_id=execution_group_id,
            crosswalk_root_id=crosswalk_root_id,
        )
