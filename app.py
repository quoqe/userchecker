import json
import httpx
import asyncio
import threading
import time
import logging
import os
from logging.handlers import RotatingFileHandler
from flask import Flask, render_template, request, jsonify, session
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.middleware.proxy_fix import ProxyFix
from config import config
import secrets
from datetime import datetime

def create_app():
    app = Flask(__name__)

    # Load configuration
    config_name = os.environ.get('FLASK_ENV', 'development')
    app.config.from_object(config[config_name])

    # Security middleware
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

    # Rate limiting setup
    def get_client_ip():
        return request.headers.get('CF-Connecting-IP',
               request.headers.get('X-Forwarded-For',
               request.headers.get('X-Real-IP', request.remote_addr)))

    limiter = Limiter(
        app=app,
        key_func=get_client_ip,
        storage_uri=app.config['RATELIMIT_STORAGE_URL'],
        default_limits=["1000 per hour"]
    )

    # Logging setup
    if not app.debug:
        if not os.path.exists('logs'):
            os.mkdir('logs')
        file_handler = RotatingFileHandler('logs/osint_app.log', maxBytes=10240000, backupCount=10)
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
        ))
        file_handler.setLevel(logging.INFO)
        app.logger.addHandler(file_handler)
        app.logger.setLevel(logging.INFO)
        app.logger.info('OSINT Username Checker startup')

    # Load sites data
    try:
        with open('wmn-data.json', 'r', encoding='utf-8') as f:
            SITES = json.load(f)
    except FileNotFoundError:
        app.logger.error("wmn-data.json not found")
        SITES = {"sites": []}

    # Global storage
    progress_store = {}
    progress_store_lock = threading.Lock()

    # IP logging
    ip_logger = logging.getLogger("ip_logger")
    ip_logger.setLevel(logging.INFO)
    ip_file_handler = RotatingFileHandler('logs/ip_logs.txt', maxBytes=5*1024*1024, backupCount=3)
    ip_file_handler.setLevel(logging.INFO)
    ip_file_handler.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
    ip_logger.addHandler(ip_file_handler)

    def sanitize_username(username):
        if not username or len(username) > 50:
            return None
        import re
        if not re.match(r'^[a-zA-Z0-9._-]+$', username):
            return None
        return username.strip()

    def generate_job_id():
        return secrets.token_urlsafe(32)

    def cleanup_progress_store():
        while True:
            try:
                now = time.time()
                with progress_store_lock:
                    expired = [job_id for job_id, data in progress_store.items()
                             if now - data.get('created', 0) > app.config['JOB_EXPIRY_SECONDS']]
                    for job_id in expired:
                        del progress_store[job_id]
                time.sleep(60)
            except Exception as e:
                app.logger.error(f"Error in cleanup thread: {e}")

    cleanup_thread = threading.Thread(target=cleanup_progress_store, daemon=True)
    cleanup_thread.start()

    @app.route('/', methods=['GET'])
    def index():
        if 'csrf_token' not in session:
            session['csrf_token'] = secrets.token_hex(16)
        return render_template('index.html')

    @app.route('/start_check', methods=['POST'])
    @limiter.limit("3 per minute")
    def start_check():
        try:
            csrf_token = request.form.get('csrf_token')
            if not csrf_token or csrf_token != session.get('csrf_token'):
                return jsonify({'error': 'Invalid CSRF token'}), 403

            username = request.form.get('username', '').strip()
            username = sanitize_username(username)
            if not username:
                return jsonify({'error': 'Invalid username format'}), 400

            client_ip = get_client_ip()
            ip_logger.info(f"{client_ip} {username}")

            job_id = generate_job_id()
            total_sites = sum(1 for site in SITES.get('sites', []) if site.get('uri_check'))

            owner = session.get('job_owner_id', secrets.token_urlsafe(16))
            session['job_owner_id'] = owner
            session.permanent = True

            with progress_store_lock:
                progress_store[job_id] = {
                    'progress': 0,
                    'total': total_sites,
                    'done': False,
                    'results': [],
                    'created': time.time(),
                    'owner': owner,
                    'username': username,
                    'ip': client_ip
                }

            threading.Thread(
                target=lambda: asyncio.run(run_check(username, job_id)),
                daemon=True
            ).start()

            return jsonify({'job_id': job_id, 'total': total_sites})

        except Exception as e:
            app.logger.error(f"Error in start_check: {e}")
            return jsonify({'error': 'Internal server error'}), 500

    @app.route('/tiktok_check', methods=['POST'])
    @limiter.limit("3 per minute")
    def tiktok_check():
        try:
            csrf_token = request.form.get('csrf_token')
            if not csrf_token or csrf_token != session.get('csrf_token'):
                return jsonify({'error': 'Invalid CSRF token'}), 403

            username = request.form.get('username', '').strip()
            username = sanitize_username(username)
            if not username:
                return jsonify({'error': 'Invalid username format'}), 400

            client_ip = get_client_ip()
            ip_logger.info(f"{client_ip} TikTok:{username}")

            # Call the TikTok API
            api_url = f"https://faas-sgp1-18bc02ac.doserverless.co/api/v1/web/fn-67a396e1-78e9-4dff-8f6a-0f07c2d80c56/default/sm-t/?username={username}"
            


            async def fetch_tiktok_data():
                try:
                    async with httpx.AsyncClient(timeout=30.0) as client:
                        response = await client.get(api_url)
                        if response.status_code == 200:
                            data = response.json()
                            return data, 200
                        elif response.status_code == 404:
                            return {'error': 'User not found'}, 404
                        else:
                            return {'error': f'API returned status {response.status_code}'}, response.status_code
                except Exception as e:
                    return {'error': f'Failed to fetch data: {str(e)}'}, 500

            # Run the async function
            result, status = asyncio.run(fetch_tiktok_data())
            return jsonify(result), status

        except Exception as e:
            app.logger.error(f"Error in tiktok_check: {e}")
            return jsonify({'error': 'Internal server error'}), 500

    @app.route('/rate_limit_status')
    def rate_limit_status():
        """Check current rate limit status for the client IP"""
        try:
            client_ip = get_client_ip()
            # Get rate limit info from limiter
            limit_key = f"3 per minute/{client_ip}"
            
            # Try to get remaining requests from limiter storage
            try:
                from flask_limiter.util import MemoryStorage
                if isinstance(limiter.storage, MemoryStorage):
                    # For memory storage, we can't easily get exact remaining count
                    # So we'll return a simple status
                    return jsonify({
                        'rate_limited': False,
                        'remaining': 3,
                        'reset_time': None
                    })
                else:
                    # For Redis or other storage backends
                    remaining = limiter.storage.get(limit_key) or 0
                    return jsonify({
                        'rate_limited': remaining >= 3,
                        'remaining': max(0, 3 - remaining),
                        'reset_time': None
                    })
            except:
                return jsonify({
                    'rate_limited': False,
                    'remaining': 3,
                    'reset_time': None
                })
        except Exception as e:
            app.logger.error(f"Error checking rate limit status: {e}")
            return jsonify({
                'rate_limited': False,
                'remaining': 3,
                'reset_time': None
            })

    async def run_check(username, job_id):
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
            timeout = httpx.Timeout(
                app.config['REQUEST_TIMEOUT'],
                connect=app.config['REQUEST_TIMEOUT'],
                read=app.config['REQUEST_TIMEOUT'],
                write=app.config['REQUEST_TIMEOUT'],
                pool=app.config['REQUEST_TIMEOUT']
            )
            semaphore = asyncio.Semaphore(app.config['MAX_CONCURRENT_REQUESTS'])

            async with httpx.AsyncClient(
                http2=True,
                timeout=timeout,
                follow_redirects=False,
                limits=httpx.Limits(max_keepalive_connections=20, max_connections=100)
            ) as client:

                async def check_site(site):
                    async with semaphore:
                        try:
                            url = site.get('uri_pretty', site['uri_check']).replace('{account}', username)
                            check_url = site['uri_check'].replace('{account}', username)
                            resp = await client.get(check_url, headers=headers)
                            found = None
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

                            with progress_store_lock:
                                if job_id in progress_store:
                                    progress_store[job_id]['results'].append({
                                        'site': site.get('name', 'Unknown'),
                                        'url': url,
                                        'found': found,
                                        'category': site.get('cat', 'misc')
                                    })
                                    progress_store[job_id]['progress'] += 1

                        except Exception as e:
                            app.logger.warning(f"Exception checking {site.get('name', 'Unknown')}: {e}")
                            with progress_store_lock:
                                if job_id in progress_store:
                                    progress_store[job_id]['results'].append({
                                        'site': site.get('name', 'Unknown'),
                                        'url': site.get('uri_pretty', site['uri_check']).replace('{account}', username),
                                        'found': None,
                                        'category': site.get('cat', 'misc')
                                    })
                                    progress_store[job_id]['progress'] += 1

                tasks = [check_site(site) for site in SITES.get('sites', []) if site.get('uri_check')]
                await asyncio.gather(*tasks, return_exceptions=True)

            with progress_store_lock:
                if job_id in progress_store:
                    progress_store[job_id]['done'] = True

        except Exception as e:
            app.logger.error(f"Error in run_check: {e}")
            with progress_store_lock:
                if job_id in progress_store:
                    progress_store[job_id]['done'] = True
                    progress_store[job_id]['error'] = 'Check failed'

    @app.route('/progress/<job_id>')
    def progress(job_id):
        try:
            owner = session.get('job_owner_id')
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
                    'results': data['results'],
                    'error': data.get('error')
                })
        except Exception as e:
            app.logger.error(f"Error in progress: {e}")
            return jsonify({'error': 'Internal server error'}), 500

    @app.route('/health')
    def health():
        return jsonify({'status': 'healthy', 'timestamp': datetime.utcnow().isoformat()})

    @app.errorhandler(404)
    def not_found(error):
        return jsonify({'error': 'Not found'}), 404

    @app.errorhandler(429)
    def ratelimit_handler(e):
        return jsonify({
            'error': 'Rate limit exceeded',
            'message': 'Too many requests. Please wait before trying again.',
            'retry_after': getattr(e, 'retry_after', 60)
        }), 429

    @app.errorhandler(500)
    def internal_error(error):
        return jsonify({'error': 'Internal server error'}), 500

    return app

if __name__ == '__main__':
    app = create_app()
    app.run(debug=False, host='0.0.0.0', port=5000)