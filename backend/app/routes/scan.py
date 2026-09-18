import json
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from ..database import get_db
from .. import models, schemas
from ..auth import get_current_user
from ..scanner import run_scan
from fpdf import FPDF
import os

router = APIRouter(prefix="/scan", tags=["scan"])

@router.get('/health')
def health():
    return {'status': 'ok'}

@router.post('/start')
def start_scan(scan: schemas.ScanCreate, db: Session = Depends(get_db), user_id: str = Depends(get_current_user)):
    try:
        result = run_scan(str(scan.url))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    s = models.Scan(user_id=int(user_id), url=str(scan.url), result=json.dumps(result))
    db.add(s)
    db.commit()
    db.refresh(s)
    return {'id': s.id, 'result': result}

@router.get('/{scan_id}')
def get_result(scan_id: int, db: Session = Depends(get_db), user_id: str = Depends(get_current_user)):
    s = db.query(models.Scan).filter(models.Scan.id == scan_id, models.Scan.user_id == int(user_id)).first()
    if not s:
        raise HTTPException(status_code=404, detail='Not found')
    return {'id': s.id, 'url': s.url, 'result': json.loads(s.result), 'created_at': s.created_at}

@router.get('/history')
def history(db: Session = Depends(get_db), user_id: str = Depends(get_current_user)):
    items = db.query(models.Scan).filter(models.Scan.user_id == int(user_id)).order_by(models.Scan.created_at.desc()).all()
    out = []
    for s in items:
        out.append({'id': s.id, 'url': s.url, 'created_at': s.created_at})
    return out

@router.get('/report/{scan_id}')
def pdf_report(scan_id: int, db: Session = Depends(get_db), user_id: str = Depends(get_current_user)):
    s = db.query(models.Scan).filter(models.Scan.id == scan_id, models.Scan.user_id == int(user_id)).first()
    if not s:
        raise HTTPException(status_code=404, detail='Not found')
    data = json.loads(s.result)
    pdf = FPDF()
    pdf.add_page()
    pdf.set_title('Web Application Attack Surface Analyzer Report')
    pdf.set_font('Arial', 'B', 16)
    pdf.cell(0, 10, 'Web Application Attack Surface Analyzer', ln=True)
    pdf.set_font('Arial', '', 11)
    pdf.cell(0, 7, 'Security analysis report', ln=True)
    pdf.set_font('Arial', '', 12)
    pdf.cell(0, 8, f'URL: {s.url}', ln=True)
    pdf.cell(0, 8, f'Date: {s.created_at}', ln=True)
    pdf.ln(4)
    pdf.set_font('Arial', 'B', 12)
    pdf.cell(0, 8, 'Security Score', ln=True)
    pdf.set_font('Arial', '', 12)
    score = data.get('score', {})
    pdf.cell(0, 8, f"Score: {score.get('score', 'N/A')} - Level: {score.get('level', 'N/A')}", ln=True)
    pdf.ln(4)
    pdf.set_font('Arial', 'B', 12)
    pdf.cell(0, 8, 'Summary', ln=True)
    pdf.set_font('Arial', '', 11)
    pdf.multi_cell(0, 6, f"This report summarizes the checks that could be completed for {s.url}. A missing resource is not treated as a security failure unless it creates a clear risk.")
    pdf.ln(3)
    pdf.set_font('Arial', 'B', 12)
    pdf.cell(0, 8, 'Findings', ln=True)
    pdf.set_font('Arial', '', 11)
    findings = data.get('findings', [])
    if findings:
        for finding in findings:
            pdf.multi_cell(0, 6, f"[{finding.get('severity', 'Info')}] {finding.get('title', 'Finding')} - {finding.get('explanation', '')}")
            pdf.multi_cell(0, 6, f"Recommendation: {finding.get('recommendation', 'Review this result.')}")
    else:
        pdf.multi_cell(0, 6, 'No findings were generated from the completed checks.')
    pdf.ln(3)
    pdf.set_font('Arial', 'B', 12)
    pdf.cell(0, 8, 'Recommendations', ln=True)
    pdf.set_font('Arial', '', 11)
    for r in data.get('recommendations', []):
        pdf.multi_cell(0, 6, f'- {r}')
    out_dir = os.path.join(os.getcwd(), '..', '..', 'reports')
    os.makedirs(out_dir, exist_ok=True)
    filename = os.path.join(out_dir, f'report_{s.id}.pdf')
    pdf.output(filename)
    return FileResponse(filename, media_type='application/pdf', filename=f'wasa-report-{s.id}.pdf')
