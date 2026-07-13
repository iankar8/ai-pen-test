# VULNERABILITY: Insecure Direct Object Reference (IDOR)
# SEVERITY: HIGH
# CWE: CWE-639
# OWASP: A01:2021 - Broken Access Control
# DESCRIPTION: No ownership validation on order access

def view_order(order_id):
    """Vulnerable to IDOR - view any order"""
    order = database.execute(
        "SELECT * FROM orders WHERE id = ?",
        (order_id,)
    )
    return render_template('order.html', order=order)

# EXPLOIT: Enumerate order_id to view all orders
# IMPACT: PII disclosure, business intelligence leakage
