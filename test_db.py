from app import get_db_connection
with get_db_connection() as conn:
    device = conn.execute('SELECT * FROM devices WHERE id = 1').fetchone()
    print(dict(device).get('cert_auto_renewal_days'))
    conn.execute('UPDATE devices SET cert_auto_renewal_days = 60 WHERE id=1')
    conn.commit()
    device = conn.execute('SELECT * FROM devices WHERE id = 1').fetchone()
    print(dict(device).get('cert_auto_renewal_days'))
