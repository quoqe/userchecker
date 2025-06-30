import json
import httpx
import uuid
import asyncio
import threading
import time
import logging
from logging.handlers import RotatingFileHandler
from flask import Flask, render_template, request, jsonify, session
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)
app.secret_key = 'change-this-secret-key'

limiter = Limiter(get_remote_address, app=app)
limiter.limit("2 per minute")(app.route('/start_check', methods=['POST']))

with open('wmn-data.json', 'r', encoding='utf-8') as f:
    SITES = json.load(f)

progress_store = {}
progress_store_lock = threading.Lock()
JOB_EXPIRY_SECONDS = 600

ip_logger = logging.getLogger("ip_logger")
ip_logger.setLevel(logging.INFO)

ip_file_handler = RotatingFileHandler('ip_logs.txt', maxBytes=5*1024*1024, backupCount=3)
ip_file_handler.setLevel(logging.INFO)
ip_file_handler.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))

ip_logger.addHandler(ip_file_handler)

def get_client_ip():
    return request.headers.get('CF-Connecting-IP', request.remote_addr)

def cleanup_progress_store():
    while True:
        now = time.time()
        with progress_store_lock:
            expired = [job_id for job_id, data in progress_store.items()
                       if now - data.get('created', 0) > JOB_EXPIRY_SECONDS]
            for job_id in expired:
                del progress_store[job_id]
        time.sleep(60)

threading.Thread(target=cleanup_progress_store, daemon=True).start()

@app.route('/', methods=['GET', 'POST'])
def index():
    return render_template('index.html')

@app.route('/start_check', methods=['POST'])
def start_check():
    username = request.form.get('username', '').strip()
    if not username:
        return jsonify({'error': 'No username provided'}), 400

    client_ip = get_client_ip()
    ip_logger.info(f"{client_ip} {username}")

    job_id = str(uuid.uuid4())
    total_sites = sum(1 for site in SITES.get('sites', []) if site.get('uri_check'))

    owner = session.get('job_owner_id', str(uuid.uuid4()))
    session['job_owner_id'] = owner

    with progress_store_lock:
        progress_store[job_id] = {
            'progress': 0,
            'total': total_sites,
            'done': False,
            'results': [],
            'created': time.time(),
            'owner': owner,
            'username': username 
        }

    threading.Thread(target=lambda: asyncio.run(run_check(username, job_id)), daemon=True).start()
    return jsonify({'job_id': job_id})

async def run_check(username, job_id):
    headers = {'User-Agent': 'Mozilla/5.0 (compatible; WhatsMyName-Flask/1.0)'}
    timeout = httpx.Timeout(15.0, connect=15.0, read=15.0, write=15.0, pool=15.0)
    semaphore = asyncio.Semaphore(20)

    async with httpx.AsyncClient(http2=True, timeout=timeout, follow_redirects=False) as client:
        async def check_site(site):
            async with semaphore:
                url = site.get('uri_pretty', site['uri_check']).replace('{account}', username)
                found = None
                try:
                    resp = await client.get(site['uri_check'].replace('{account}', username), headers=headers)
                    e_string = site.get('e_string', '').replace('{account}', username) if 'e_string' in site else None
                    m_string = site.get('m_string', '').replace('{account}', username) if 'm_string' in site else None

                    if 'e_code' in site and resp.status_code == int(site['e_code']):
                        if e_string:
                            found = e_string in resp.text
                        else:
                            found = True
                    else:
                        m_codes = site.get('m_code')
                        m_code_matched = False
                        if m_codes is not None:
                            if isinstance(m_codes, list):
                                if resp.status_code in m_codes:
                                    found = False
                                    m_code_matched = True
                            else:
                                if resp.status_code == int(m_codes):
                                    found = False
                                    m_code_matched = True
                        if not m_code_matched and m_string and m_string in resp.text:
                            found = False
                        if found is None:
                            found = False
                except Exception as e:
                    logging.warning(f"Exception checking {url}: {e}", exc_info=True)
                    found = None
                with progress_store_lock:
                    if job_id in progress_store:
                        progress_store[job_id]['results'].append({
                            'site': site.get('name', 'Unknown'),
                            'url': url,
                            'found': found
                        })
                        progress_store[job_id]['progress'] += 1

        tasks = [check_site(site) for site in SITES.get('sites', []) if site.get('uri_check')]
        await asyncio.gather(*tasks)
    with progress_store_lock:
        if job_id in progress_store:
            progress_store[job_id]['done'] = True

@app.route('/progress/<job_id>')
def progress(job_id):
    owner = session.get('job_owner_id')
    client_ip = get_client_ip()
    with progress_store_lock:
        data = progress_store.get(job_id)
        if not data or data.get('owner') != owner:
            return jsonify({'error': 'Invalid or unauthorized job id'}), 404
        percent = int(100 * data['progress'] / data['total']) if data['total'] else 100
        return jsonify({
            'progress': data['progress'],
            'total': data['total'],
            'percent': percent,
            'done': data['done'],
            'results': data['results']
        })

if __name__ == '__main__':
    app.run(debug=False)
