import json
import psycopg2
from psycopg2.extras import RealDictCursor
from datetime import datetime

class DateTimeEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        return super(DateTimeEncoder, self).default(obj)

conn = psycopg2.connect('postgresql://fraudshield:fraudshield@postgres:5432/fraudshield')
cur = conn.cursor(cursor_factory=RealDictCursor)

cur.execute('''
    SELECT 
        s.id, 
        s.original_filename, 
        v.final_risk_score,
        v.severity_band,
        v.recommended_action,
        llm.summary_text,
        llm.ttp_mapping,
        m.classifier_score,
        m.novelty_score,
        st.permissions,
        st.obfuscation_score,
        dy.sms_access,
        dy.accessibility_abuse,
        dy.overlay_detected,
        dy.network_calls
    FROM apk_submissions s
    LEFT JOIN risk_verdicts v ON v.submission_id = s.id
    LEFT JOIN llm_reports llm ON llm.submission_id = s.id
    LEFT JOIN ml_scores m ON m.submission_id = s.id
    LEFT JOIN static_findings st ON st.submission_id = s.id
    LEFT JOIN dynamic_findings dy ON dy.submission_id = s.id
    WHERE s.status = 'completed'
    ORDER BY s.submitted_at DESC
''')
rows = cur.fetchall()

print(json.dumps(rows, indent=2, cls=DateTimeEncoder))
