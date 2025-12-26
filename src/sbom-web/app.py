from fastapi import FastAPI, File, UploadFile, Request, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional

from spdx_tools.spdx.parser.parse_anything import parse_file  # 會依副檔名/內容嘗試解析
from spdx_tools.spdx.model.document import Document as SpdxDocument
import tempfile
import os

def spdx_doc_to_viewmodel(doc: SpdxDocument) -> dict:
    """
    將 spdx-tools 的 Document 轉成可丟給 Jinja2 的 dict（MVP 欄位）。
    """
    creation = doc.creation_info
    packages = []
    for p in doc.packages:
        # license_declared 可能是 None 或 Expression；保守轉字串
        packages.append({
            "spdx_id": p.spdx_id,
            "name": p.name,
            "version": p.version,
            "supplier": str(p.supplier) if p.supplier else None,
            "download_location": p.download_location,
            "license_declared": str(p.license_declared) if p.license_declared else None,
            "license_concluded": str(p.license_concluded) if p.license_concluded else None,
            "purl": p.external_references[0].locator if (p.external_references and len(p.external_references)>0 and getattr(p.external_references[0], "reference_type", None)) else None
        })

    return {
        "spdx_version": doc.spdx_version,
        "data_license": doc.data_license,
        "document_namespace": doc.document_namespace,
        "document_name": creation.document_name if creation else None,
        "created": creation.created.isoformat() if creation and creation.created else None,
        "creators": [str(c) for c in creation.creators] if creation and creation.creators else [],
        "packages": packages,
    }

def parse_spdx(upload_filename: str, content: bytes) -> dict:
    """
    使用 spdx-tools 解析 SPDX。
    parse_file() 需要檔案路徑，因此用暫存檔落地（只在 /tmp，處理完即刪）。
    """
    suffix = os.path.splitext(upload_filename)[1].lower() or ".txt"

    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        tmp.write(content)
        tmp_path = tmp.name

    try:
        doc = parse_file(tmp_path)  # 會依檔案格式解析（RDF/XML、JSON、YAML、Tag/Value 等）:contentReference[oaicite:1]{index=1}
        return spdx_doc_to_viewmodel(doc)
    finally:
        try:
            os.remove(tmp_path)
        except OSError:
            pass


app = FastAPI()
templates = Jinja2Templates(directory="templates")

MAX_UPLOAD_BYTES = 5 * 1024 * 1024  # 5MB，可自行調整


def _strip_ns(tag: str) -> str:
    # 將 {namespace}tag 轉成 tag
    if "}" in tag:
        return tag.split("}", 1)[1]
    return tag


def parse_cyclonedx_xml(xml_bytes: bytes) -> Dict[str, Any]:
    """
    CycloneDX XML 解析（MVP）：
    - 讀 bom 上的 serialNumber / version
    - metadata (timestamp, tools, component)
    - components (name, version, purl, bom-ref, type, licenses)
    - dependencies (bom-ref -> dependsOn[])
    """
    try:
        root = ET.fromstring(xml_bytes)
    except ET.ParseError as e:
        raise HTTPException(status_code=400, detail=f"XML 解析失敗：{e}")

    # 尋找常見欄位（以 namespace 無關方式處理）
    bom = root
    if _strip_ns(bom.tag) != "bom":
        raise HTTPException(status_code=400, detail="看起來不是 CycloneDX bom 根節點（<bom>）")

    bom_info: Dict[str, Any] = {
        "serialNumber": bom.attrib.get("serialNumber"),
        "version": bom.attrib.get("version"),
        "metadata": {},
        "components": [],
        "dependencies": [],
    }

    # helper: 遍歷時忽略 namespace，靠 local-name 找
    def find_child(parent: ET.Element, name: str) -> Optional[ET.Element]:
        for ch in list(parent):
            if _strip_ns(ch.tag) == name:
                return ch
        return None

    def find_children(parent: ET.Element, name: str) -> List[ET.Element]:
        return [ch for ch in list(parent) if _strip_ns(ch.tag) == name]

    # metadata
    md = find_child(bom, "metadata")
    if md is not None:
        timestamp = find_child(md, "timestamp")
        tools = find_child(md, "tools")
        md_component = find_child(md, "component")

        tool_list = []
        if tools is not None:
            # CycloneDX 有 tool / tools / components 等不同版本表達；先用最常見 tool
            for tool in find_children(tools, "tool"):
                vendor = find_child(tool, "vendor")
                name = find_child(tool, "name")
                version = find_child(tool, "version")
                tool_list.append({
                    "vendor": vendor.text.strip() if vendor is not None and vendor.text else None,
                    "name": name.text.strip() if name is not None and name.text else None,
                    "version": version.text.strip() if version is not None and version.text else None,
                })

        md_comp_obj = None
        if md_component is not None:
            md_comp_obj = {
                "type": md_component.attrib.get("type"),
                "bom-ref": md_component.attrib.get("bom-ref"),
                "name": (find_child(md_component, "name").text.strip()
                         if find_child(md_component, "name") is not None and find_child(md_component, "name").text else None),
                "version": (find_child(md_component, "version").text.strip()
                            if find_child(md_component, "version") is not None and find_child(md_component, "version").text else None),
                "purl": (find_child(md_component, "purl").text.strip()
                         if find_child(md_component, "purl") is not None and find_child(md_component, "purl").text else None),
            }

        bom_info["metadata"] = {
            "timestamp": timestamp.text.strip() if timestamp is not None and timestamp.text else None,
            "tools": tool_list,
            "component": md_comp_obj,
        }

    # components
    comps = find_child(bom, "components")
    components_out: List[Dict[str, Any]] = []
    if comps is not None:
        for c in find_children(comps, "component"):
            name_el = find_child(c, "name")
            ver_el = find_child(c, "version")
            purl_el = find_child(c, "purl")

            # licenses（簡化抓法：取 license -> id / name / text 的其中一個）
            licenses_out = []
            licenses_el = find_child(c, "licenses")
            if licenses_el is not None:
                for licwrap in find_children(licenses_el, "license"):
                    lic_id = find_child(licwrap, "id")
                    lic_name = find_child(licwrap, "name")
                    lic_text = find_child(licwrap, "text")
                    licenses_out.append(
                        (lic_id.text.strip() if lic_id is not None and lic_id.text else None) or
                        (lic_name.text.strip() if lic_name is not None and lic_name.text else None) or
                        ("(license text)" if lic_text is not None else None)
                    )

            components_out.append({
                "type": c.attrib.get("type"),
                "bom-ref": c.attrib.get("bom-ref"),
                "name": name_el.text.strip() if name_el is not None and name_el.text else None,
                "version": ver_el.text.strip() if ver_el is not None and ver_el.text else None,
                "purl": purl_el.text.strip() if purl_el is not None and purl_el.text else None,
                "licenses": [x for x in licenses_out if x],
            })

    bom_info["components"] = components_out

    # dependencies
    deps = find_child(bom, "dependencies")
    deps_out = []
    if deps is not None:
        for dep in find_children(deps, "dependency"):
            ref = dep.attrib.get("ref")
            depends_on = [d.attrib.get("ref") for d in find_children(dep, "dependency") if d.attrib.get("ref")]
            deps_out.append({"ref": ref, "dependsOn": depends_on})

    bom_info["dependencies"] = deps_out
    return bom_info


@app.get("/", response_class=HTMLResponse)
def upload_page(request: Request):
    return templates.TemplateResponse("upload.html", {"request": request})

@app.post("/upload", response_class=HTMLResponse)
async def upload_sbom(request: Request, file: UploadFile = File(...)):
    filename = file.filename or "uploaded"
    content = await file.read()

    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="檔案太大，請縮小後再上傳（目前限制 5MB）")

    ext = os.path.splitext(filename)[1].lower()

    # 1) 先嘗試 CycloneDX XML：副檔名 xml 且根節點 <bom> 才當 CycloneDX
    if ext == ".xml":
        try:
            cyclonedx = parse_cyclonedx_xml(content)
            return templates.TemplateResponse(
                "report_cyclonedx.html",
                {"request": request, "sbom": cyclonedx, "filename": filename}
            )
        except HTTPException:
            # 不是 CycloneDX 或解析失敗 → 往下嘗試 SPDX（RDF/XML 也常用 .xml）
            pass

    # 2) SPDX（可吃 .spdx .rdf .xml .json .yml .yaml .tv .txt 等）
    try:
        spdx_vm = parse_spdx(filename, content)
        return templates.TemplateResponse(
            "report_spdx.html",
            {"request": request, "spdx": spdx_vm, "filename": filename}
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"無法判斷或解析 SBOM：{e}")
