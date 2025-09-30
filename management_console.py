from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_httpauth import HTTPBasicAuth
from werkzeug.security import generate_password_hash, check_password_hash
import json
import redis
import time
from datetime import datetime
import socket
from dnslib import DNSRecord, QTYPE, RCODE, DNSQuestion

app = Flask(__name__)
app.secret_key = 'supersecretkey'
CONFIG_PATH = 'config.json'
auth = HTTPBasicAuth()

# --- User credentials ---
# In a real application, store this securely
users = {
    "admin": generate_password_hash("Srv@12345?!")
}

@auth.verify_password
def verify_password(username, password):
    if username in users and \
            check_password_hash(users.get(username), password):
        return username

# --- Load Config ---
with open(CONFIG_PATH, 'r') as f:
    config = json.load(f)

# --- Redis Connection (using the synchronous client for Flask) ---
redis_client = redis.Redis(
    host=config['redis']['host'],
    port=config['redis']['port'],
    db=config['redis']['db']
)

# --- New Resilient Lookup Tool ---
def resilient_lookup(domain, qtype_str):
    """
    A resilient lookup function that mirrors the main server's failover logic.
    """
    try:
        # *** THE FIX IS HERE: Convert qtype string to integer value correctly ***
        qtype_int = getattr(QTYPE, qtype_str, QTYPE.A) # Default to 'A' if invalid
        q = DNSRecord(q=DNSQuestion(domain, qtype_int))
        request_bytes = q.pack()

        for ns in config['forwarders']:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                    sock.settimeout(5)
                    sock.sendto(request_bytes, (ns, 53))
                    response_bytes, _ = sock.recvfrom(4096)
                    
                    if len(response_bytes) >= 4:
                        rcode = response_bytes[3] & 0x0F
                        if rcode in [RCODE.NOERROR, RCODE.NXDOMAIN]:
                            return DNSRecord.parse(response_bytes)
                        else:
                            continue # Try next forwarder on failure
            except socket.timeout:
                continue # Try next forwarder on timeout
        return None # All forwarders failed
    except Exception as e:
        # Re-raise with a more informative message if it's a QTYPE error
        if isinstance(e, AttributeError):
             raise Exception(f"Invalid QTYPE specified: {qtype_str}")
        raise Exception(f"Lookup failed: {e}")


@app.route('/')
@auth.login_required
def index():
    # This route just renders the main page structure.
    # Data will be loaded via JavaScript.
    with open(CONFIG_PATH, 'r') as f:
        current_config = json.load(f)
        forwarders = current_config['forwarders']
    return render_template('index.html', forwarders=forwarders)

@app.route('/api/stats')
@auth.login_required
def api_stats():
    """
    API endpoint to fetch stats and cached records efficiently.
    """
    cached_items = []
    try:
        keys = list(redis_client.scan_iter("dns:*:*"))
        total_cached = len(keys)
        
        # Use a pipeline to fetch all data in one go for high performance
        if keys:
            pipe = redis_client.pipeline()
            for key in keys:
                pipe.get(f"{key.decode('utf-8')}:hits")
                pipe.ttl(key)
            results = pipe.execute()
        
            for i, key in enumerate(keys):
                key_str = key.decode('utf-8')
                parts = key_str.split(':')
                if len(parts) == 3:
                    hits = results[i * 2]
                    ttl = results[i * 2 + 1]
                    cached_items.append({
                        'domain': parts[1],
                        'qtype_name': parts[2],
                        'request_count': int(hits.decode('utf-8')) if hits else 0,
                        'expiry_timestamp': time.time() + ttl if ttl and ttl > -1 else 0
                    })
        
        cached_items.sort(key=lambda x: x['request_count'], reverse=True)

    except redis.exceptions.ConnectionError:
        return jsonify({"error": "Could not connect to Redis."}), 500
    
    return jsonify({
        'total_cached': total_cached,
        'cached_items': cached_items
    })


@app.route('/lookup', methods=['POST'])
@auth.login_required
def lookup():
    domain = request.form['domain']
    qtype_str = request.form['qtype']
    
    try:
        response = resilient_lookup(domain, qtype_str)
        if response:
            flash(f"Lookup for '{domain}' ({qtype_str}):\n{str(response)}", 'success')
        else:
            flash(f"Lookup for '{domain}' ({qtype_str}) failed: All forwarders were unable to resolve.", 'danger')
    except Exception as e:
        flash(f"An error occurred during lookup: {e}", 'danger')
        
    return redirect(url_for('index'))

@app.route('/forwarders/add', methods=['POST'])
@auth.login_required
def add_forwarder():
    new_forwarder = request.form['forwarder_ip']
    if new_forwarder:
        with open(CONFIG_PATH, 'r+') as f:
            current_config = json.load(f)
            if new_forwarder not in current_config['forwarders']:
                current_config['forwarders'].append(new_forwarder)
                f.seek(0)
                json.dump(current_config, f, indent=2)
                f.truncate()
                flash(f"Forwarder {new_forwarder} added.", 'success')
            else:
                flash(f"Forwarder {new_forwarder} already exists.", 'warning')
    return redirect(url_for('index'))

@app.route('/forwarders/delete', methods=['POST'])
@auth.login_required
def delete_forwarder():
    forwarder_to_delete = request.form['forwarder_ip']
    with open(CONFIG_PATH, 'r+') as f:
        current_config = json.load(f)
        if forwarder_to_delete in current_config['forwarders']:
            current_config['forwarders'].remove(forwarder_to_delete)
            f.seek(0)
            json.dump(current_config, f, indent=2)
            f.truncate()
            flash(f"Forwarder {forwarder_to_delete} removed.", 'success')
        else:
            flash(f"Forwarder {forwarder_to_delete} not found.", 'danger')
    return redirect(url_for('index'))


# A helper function to make strftime available in templates
def format_datetime(timestamp, fmt):
    if not isinstance(timestamp, (int, float)) or timestamp <= 0:
        return "N/A"
    return datetime.utcfromtimestamp(timestamp).strftime(fmt)

# We must register the filter outside of the main block for Gunicorn
app.jinja_env.filters['strftime'] = format_datetime

if __name__ == '__main__':
    # Use Flask's development server, not Gunicorn, for direct execution
    app.run(host='0.0.0.0', port=5000, debug=True)


