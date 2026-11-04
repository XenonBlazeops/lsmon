"""Import a validated, normalized cloud posture report; no scanner or cloud SDK is used."""
import hashlib, json
from datetime import datetime
from urllib.parse import urlparse
from django.utils import timezone
from lsmon_core.models import CloudPostureAssessmentRun, CloudPostureConnector, SecurityFinding

SEVERITIES={"critical":"critical","high":"high","medium":"medium","low":"low","informational":"informational"}
def safe_url(value):
    value=str(value or "").strip(); parsed=urlparse(value)
    return value if parsed.scheme=="https" and parsed.netloc else ""
def normalize(document, provider):
    if not isinstance(document,dict) or document.get("format")!="tecstaq_cloud_posture_report_v1" or not isinstance(document.get("findings"),list): raise ValueError("unsupported_report_format")
    output=[]
    for item in document["findings"]:
        if not isinstance(item,dict) or str(item.get("status","")).lower() not in {"fail","failed"}: continue
        control=str(item.get("control_id","")).strip()[:160]; resource=str(item.get("resource_id","")).strip()[:255]
        if not control or not resource: continue
        severity=SEVERITIES.get(str(item.get("severity","")).lower(),"medium")
        source_id=hashlib.sha256((provider+"|"+control+"|"+resource).encode()).hexdigest()
        output.append({"source_id":source_id,"control_id":control,"title":str(item.get("title") or control)[:300],"severity":severity,"remediation_url":safe_url(item.get("remediation_url"))})
    return output
def import_report(tenant_slug, credential_reference, report_path):
    connector=CloudPostureConnector.objects.get(tenant__slug=tenant_slug,credential_reference=credential_reference)
    rows=normalize(json.loads(open(report_path,encoding="utf-8").read()),connector.provider)
    run=CloudPostureAssessmentRun.objects.create(connector=connector,status="running")
    now=timezone.now(); created=updated=0
    for row in rows:
        finding, was_created=SecurityFinding.objects.get_or_create(tenant=connector.tenant,source=SecurityFinding.Source.PROWLER,source_id=row["source_id"],defaults={**row,"description":"Normalized cloud posture control failure.","cve_id":"","asset":None,"owner":"","evidence_reference":"cloud-control:"+row["control_id"],"first_observed_at":now,"last_observed_at":now})
        if was_created: created+=1
        else:
            finding.title=row["title"]; finding.control_id=row["control_id"]; finding.severity=row["severity"]; finding.remediation_url=row["remediation_url"]; finding.last_observed_at=now; finding.save(update_fields=["title","control_id","severity","remediation_url","last_observed_at","updated_at"]); updated+=1
    run.status="succeeded"; run.completed_at=timezone.now(); run.finding_count=len(rows); run.save(update_fields=["status","completed_at","finding_count"])
    return created,updated,len(rows)
