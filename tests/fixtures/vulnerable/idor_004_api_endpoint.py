# VULNERABILITY: Insecure Direct Object Reference (IDOR)
# SEVERITY: HIGH
# CWE: CWE-639
# OWASP: A01:2021 - Broken Access Control
# DESCRIPTION: API endpoint without authorization

def api_get_invoice(invoice_id):
    """Vulnerable to IDOR via API"""
    invoice = Invoice.query.filter_by(id=invoice_id).first()
    return jsonify(invoice.to_dict())

# EXPLOIT: GET /api/invoice/123 -> access any invoice
# IMPACT: Financial data exposure
