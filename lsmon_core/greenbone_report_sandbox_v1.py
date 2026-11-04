"""Offline Greenbone/OpenVAS XML normalization contract; no network or scanner access."""
import hashlib
import xml.etree.ElementTree as ET
SEV={"critical":"critical","high":"high","medium":"medium","low":"low","log":"informational","none":"informational"}
def normalize(xml_text, tenant_scope):
 root=ET.fromstring(xml_text);out=[]
 for r in root.findall('.//result'):
  threat=(r.findtext('threat') or '').strip().lower();host=(r.findtext('host') or '').strip();nvt=r.find('nvt');oid=(nvt.get('oid') if nvt is not None else '') or '';name=(nvt.findtext('name') if nvt is not None else '') or oid
  if threat not in ('critical','high','medium','low') or not host or not oid:continue
  sid=hashlib.sha256((tenant_scope+'|'+host+'|'+oid).encode()).hexdigest()
  out.append({'source':'greenbone','source_id':sid,'title':name[:300],'control_id':oid[:160],'severity':SEV[threat],'asset_hint':host[:255]})
 return out
