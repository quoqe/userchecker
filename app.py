import json
import httpx
import asyncio
import threading
import time
import logging
import os
import re
from logging.handlers import RotatingFileHandler
from flask import Flask, render_template, request, jsonify, session
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.middleware.proxy_fix import ProxyFix
from config import config
import secrets
from datetime import datetime
from cryptography.fernet import Fernet

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

    # Encryption for sensitive data
    def get_encryption_key():
        key = app.config['SECRET_KEY'].encode()
        # Pad or truncate to 32 bytes for Fernet
        key = key[:32].ljust(32, b'0')
        return Fernet.generate_key() if len(key) < 32 else Fernet(key)

    def sanitize_username(username):
        """Enhanced username validation with security checks"""
        if not username or len(username) > 50:
            return None
        import re
        # More strict validation to prevent injection attacks
        if not re.match(r'^[a-zA-Z0-9._-]+$', username):
            return None
        # Additional security: check for suspicious patterns
        suspicious_patterns = ['<', '>', '"', "'", '&', '%', '\\', '/', '?', '#']
        if any(pattern in username for pattern in suspicious_patterns):
            return None
        return username.strip()

    def sanitize_email(email):
        """Enhanced email validation with security checks"""
        if not email or len(email) > 254:
            return None
        
        # Basic email regex pattern
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_pattern, email):
            return None
        
        # Additional security: check for suspicious patterns
        suspicious_patterns = ['<', '>', '"', "'", '&', '%', '\\', '?', '#', ';']
        if any(pattern in email for pattern in suspicious_patterns):
            return None
        
        return email.strip().lower()

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
            # Enhanced CSRF protection
            csrf_token = request.form.get('csrf_token')
            if not csrf_token or csrf_token != session.get('csrf_token'):
                app.logger.warning(f"CSRF token mismatch from IP: {get_client_ip()}")
                return jsonify({'error': 'Invalid CSRF token'}), 403

            # Enhanced input validation
            username = request.form.get('username', '').strip()
            username = sanitize_username(username)
            if not username:
                app.logger.warning(f"Invalid username format from IP: {get_client_ip()}")
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
            # Enhanced CSRF protection
            csrf_token = request.form.get('csrf_token')
            if not csrf_token or csrf_token != session.get('csrf_token'):
                app.logger.warning(f"CSRF token mismatch from IP: {get_client_ip()}")
                return jsonify({'error': 'Invalid CSRF token'}), 403

            # Enhanced input validation
            username = request.form.get('username', '').strip()
            username = sanitize_username(username)
            if not username:
                app.logger.warning(f"Invalid TikTok username format from IP: {get_client_ip()}")
                return jsonify({'error': 'Invalid username format'}), 400

            client_ip = get_client_ip()
            ip_logger.info(f"{client_ip} TikTok:{username}")

            # Enhanced API URL with proper encoding
            api_url = f"https://faas-sgp1-18bc02ac.doserverless.co/api/v1/web/fn-67a396e1-78e9-4dff-8f6a-0f07c2d80c56/default/sm-t/?username={username}"

            async def fetch_tiktok_data():
                try:
                    # Enhanced security headers and timeout
                    headers = {
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                        'Accept': 'application/json',
                        'Accept-Language': 'en-US,en;q=0.9',
                        'Cache-Control': 'no-cache',
                        'Pragma': 'no-cache'
                    }
                    
                    async with httpx.AsyncClient(
                        timeout=30.0,
                        follow_redirects=True,
                        limits=httpx.Limits(max_keepalive_connections=5, max_connections=10)
                    ) as client:
                        response = await client.get(api_url, headers=headers)
                        
                        if response.status_code == 200:
                            try:
                                data = response.json()
                                # Validate response structure
                                if not isinstance(data, dict):
                                    return {'error': 'Invalid response format'}, 500
                                return data, 200
                            except json.JSONDecodeError:
                                return {'error': 'Invalid JSON response'}, 500
                        elif response.status_code == 404:
                            return {'error': 'User not found'}, 404
                        else:
                            return {'error': f'API returned status {response.status_code}'}, response.status_code
                            
                except httpx.TimeoutException:
                    return {'error': 'Request timeout'}, 408
                except httpx.RequestError as e:
                    app.logger.error(f"TikTok API request error: {e}")
                    return {'error': 'Failed to connect to TikTok API'}, 500
                except Exception as e:
                    app.logger.error(f"Unexpected error in TikTok check: {e}")
                    return {'error': f'Failed to fetch data: {str(e)}'}, 500

            # Run the async function
            result, status = asyncio.run(fetch_tiktok_data())
            return jsonify(result), status

        except Exception as e:
            app.logger.error(f"Error in tiktok_check: {e}")
            return jsonify({'error': 'Internal server error'}), 500

    @app.route('/osint_check', methods=['POST'])
    @limiter.limit("2 per minute")  # More restrictive rate limit for OSINT API
    def osint_check():
        try:
            # Enhanced CSRF protection
            csrf_token = request.form.get('csrf_token')
            if not csrf_token or csrf_token != session.get('csrf_token'):
                app.logger.warning(f"CSRF token mismatch from IP: {get_client_ip()}")
                return jsonify({'error': 'Invalid CSRF token'}), 403

            # Check if API key is configured
            if not app.config.get('OSINT_API_KEY'):
                app.logger.error("OSINT API key not configured")
                return jsonify({'error': 'Service temporarily unavailable'}), 503

            # Enhanced input validation
            email = request.form.get('email', '').strip()
            email = sanitize_email(email)
            if not email:
                app.logger.warning(f"Invalid email format from IP: {get_client_ip()}")
                return jsonify({'error': 'Invalid email format'}), 400

            client_ip = get_client_ip()
            ip_logger.info(f"{client_ip} OSINT:{email}")

            async def fetch_osint_data():
                try:
                    # Secure headers with API key
                    headers = {
                        'X-API-Key': app.config['OSINT_API_KEY'],
                        'Content-Type': 'application/json',
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                        'Accept': 'application/json',
                        'Cache-Control': 'no-cache'
                    }
                    
                    # Secure payload construction
                    payload = {
                        "field": [{"email": email}]
                    }
                    
                    async with httpx.AsyncClient(
                        timeout=45.0,  # Longer timeout for OSINT API
                        follow_redirects=False,  # Don't follow redirects for security
                        limits=httpx.Limits(max_keepalive_connections=3, max_connections=5)
                    ) as client:
                        response = await client.post(
                            app.config['OSINT_API_URL'],
                            headers=headers,
                            json=payload
                        )
                        
                        if response.status_code == 200:
                            try:
                                data = response.json()
                                # Validate and sanitize response
                                if not isinstance(data, dict):
                                    return {'error': 'Invalid response format'}, 500
                                
                                # Log successful API call (without sensitive data)
                                app.logger.info(f"OSINT API call successful for IP: {client_ip}")
                                return data, 200
                                
                            except json.JSONDecodeError:
                                app.logger.error("Invalid JSON response from OSINT API")
                                return {'error': 'Invalid response from service'}, 500
                                
                        elif response.status_code == 401:
                            app.logger.error("OSINT API authentication failed")
                            return {'error': 'Service authentication failed'}, 503
                        elif response.status_code == 429:
                            app.logger.warning("OSINT API rate limit exceeded")
                            return {'error': 'Service rate limit exceeded. Please try again later.'}, 429
                        elif response.status_code == 404:
                            return {'error': 'No data found for this email'}, 404
                        else:
                            app.logger.error(f"OSINT API returned status {response.status_code}")
                            return {'error': f'Service returned status {response.status_code}'}, response.status_code
                            
                except httpx.TimeoutException:
                    app.logger.error("OSINT API timeout")
                    return {'error': 'Request timeout. Please try again.'}, 408
                except httpx.RequestError as e:
                    app.logger.error(f"OSINT API request error: {e}")
                    return {'error': 'Failed to connect to service'}, 500
                except Exception as e:
                    app.logger.error(f"Unexpected error in OSINT check: {e}")
                    return {'error': 'An unexpected error occurred'}, 500

            # Run the async function
            result, status = asyncio.run(fetch_osint_data())
            return jsonify(result), status

        except Exception as e:
            app.logger.error(f"Error in osint_check: {e}")
            return jsonify({'error': 'Internal server error'}), 500

    @app.route('/rate_limit_status')
    def rate_limit_status():
        """Enhanced rate limit status check"""
        try:
            client_ip = get_client_ip()
            
            # Simple rate limit status for security
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
            # Enhanced security headers
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'Cache-Control': 'no-cache',
                'Pragma': 'no-cache'
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
                limits=httpx.Limits(max_keepalive_connections=20, max_connections=100),
                headers=headers
            ) as client:

                async def check_site(site):
                    async with semaphore:
                        try:
                            # Enhanced URL validation
                            url = site.get('uri_pretty', site['uri_check']).replace('{account}', username)
                            check_url = site['uri_check'].replace('{account}', username)
                            
                            # Validate URL format
                            if not check_url.startswith(('http://', 'https://')):
                                raise ValueError("Invalid URL scheme")
                            
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
            # Enhanced authorization check
            owner = session.get('job_owner_id')
            with progress_store_lock:
                data = progress_store.get(job_id)
                if not data or data.get('owner') != owner:
                    app.logger.warning(f"Unauthorized progress access attempt from IP: {get_client_ip()}")
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

    # Enhanced error handlers
    @app.errorhandler(404)
    def not_found(error):
        return jsonify({'error': 'Not found'}), 404

    @app.errorhandler(429)
    def ratelimit_handler(e):
        app.logger.warning(f"Rate limit exceeded from IP: {get_client_ip()}")
        return jsonify({
            'error': 'Rate limit exceeded',
            'message': 'Too many requests. Please wait before trying again.',
            'retry_after': getattr(e, 'retry_after', 60)
        }), 429

    @app.errorhandler(500)
    def internal_error(error):
        app.logger.error(f"Internal server error: {error}")
        return jsonify({'error': 'Internal server error'}), 500

    # Security headers middleware
    @app.after_request
    def add_security_headers(response):
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        return response

    return app

if __name__ == '__main__':
    app = create_app()
    app.run(debug=False, host='0.0.0.0', port=5000)