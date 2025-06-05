from flask import Flask, request, redirect, render_template, url_for, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from sqlalchemy.sql import func
import string
import random
import requests
import user_agents

from dotenv import load_dotenv
import os

load_dotenv()  # Load environment variables from .env file if present

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///grabify.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Models
class URLMap(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    original_url = db.Column(db.String(2048), nullable=False)
    short_id = db.Column(db.String(10), unique=True, nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), server_default=func.now())
    visits = db.relationship('Visit', backref='urlmap', lazy=True)

class Visit(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    urlmap_id = db.Column(db.Integer, db.ForeignKey('url_map.id'), nullable=False)
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.String(512))
    browser = db.Column(db.String(128))
    os = db.Column(db.String(128))
    referrer = db.Column(db.String(2048))
    country = db.Column(db.String(128))
    city = db.Column(db.String(128))
    region = db.Column(db.String(128))
    region_code = db.Column(db.String(32))
    postal_code = db.Column(db.String(32))
    utc_offset = db.Column(db.String(32))
    network = db.Column(db.String(256))
    asn = db.Column(db.String(64))
    country_iso_code = db.Column(db.String(16))
    capital = db.Column(db.String(128))
    tld = db.Column(db.String(16))
    continent = db.Column(db.String(64))
    eu = db.Column(db.String(8))
    currency = db.Column(db.String(64))
    country_area = db.Column(db.String(64))
    country_population = db.Column(db.String(64))
    latitude = db.Column(db.String(64))
    longitude = db.Column(db.String(64))
    screen_size = db.Column(db.String(64))
    color_scheme = db.Column(db.String(32))
    hdr_screen = db.Column(db.String(8))
    gpu = db.Column(db.String(256))
    platform = db.Column(db.String(64))
    timezone = db.Column(db.String(64))
    user_time = db.Column(db.String(64))
    language = db.Column(db.String(32))
    incognito = db.Column(db.String(8))
    ad_blocker = db.Column(db.String(8))
    orientation = db.Column(db.String(32))
    hostname = db.Column(db.String(256))
    isp = db.Column(db.String(256))
    timestamp = db.Column(db.DateTime(timezone=True), server_default=func.now())

# Helper functions
def generate_short_id(num_chars=6):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=num_chars))

import time
import logging

import os

# Cache for IP info to prevent repeat lookups
_ip_info_cache = {}

def get_ip_info(ip):
    """
    Fetch extended IP metadata including region, region_code, postal_code, utc_offset, network, asn, country_iso_code, capital, tld, continent, eu, currency, country_area, country_population.
    Returns a dict with all these keys.
    Handles localhost and private IPs gracefully.
    Retries once after 1 second if incomplete data is returned.
    Logs incomplete data for debugging.
    Uses fallback to ipinfo.io API if ipapi.co fails or returns incomplete data.
    Uses additional fallback to ipgeolocation.io API for better city accuracy.
    Implements caching to prevent repeat lookups.
    Handles API quota errors and logs them.
    """
    API_KEY = os.getenv('IPGEOLOCATION_API_KEY')
    if not API_KEY:
        logging.error("IPGEOLOCATION_API_KEY environment variable not set.")
    if ip in _ip_info_cache:
        return _ip_info_cache[ip]
    info = {
        'country': 'Unknown',
        'city': 'Unknown',
        'region': '',
        'region_code': '',
        'postal_code': '',
        'utc_offset': '',
        'network': '',
        'asn': '',
        'country_iso_code': '',
        'capital': '',
        'tld': '',
        'continent': '',
        'eu': '',
        'currency': '',
        'country_area': '',
        'country_population': '',
        'hostname': 'Unknown',
        'isp': 'Unknown',
        'latitude': '',
        'longitude': ''
    }
    try:
        if ip == '127.0.0.1' or ip == '::1':
            info['country'] = 'Localhost'
            info['city'] = 'Localhost'
            info['hostname'] = 'Localhost'
            info['isp'] = 'Localhost'
            info['latitude'] = ''
            info['longitude'] = ''
            _ip_info_cache[ip] = info
            return info
        for attempt in range(2):  # Try twice
            try:
                response = requests.get(f'https://ipapi.co/{ip}/json/')
                if response.status_code == 429:
                    logging.error(f"API quota exceeded for ipapi.co on IP {ip}")
                    break
                elif response.status_code == 200:
                    data = response.json()
                    info['country'] = data.get('country_name', 'Unknown') or 'Unknown'
                    info['city'] = data.get('city', 'Unknown') or 'Unknown'
                    info['region'] = data.get('state_prov', '') or ''
                    info['region_code'] = data.get('state_code', '') or ''
                    info['postal_code'] = data.get('zipcode', '') or ''
                    info['network'] = data.get('network', '') or ''
                    info['asn'] = data.get('asn', '') or ''
                    info['hostname'] = data.get('hostname', 'Unknown') or 'Unknown'
                    info['isp'] = data.get('org', 'Unknown') or 'Unknown'
                    info['latitude'] = str(data.get('latitude', '')) or ''
                    info['longitude'] = str(data.get('longitude', '')) or ''
                    info['utc_offset'] = data.get('time_zone', {}).get('offset', '') or ''
                    info['country_iso_code'] = data.get('country_code2', '') or ''
                    info['capital'] = data.get('country_capital', '') or ''
                    info['tld'] = data.get('country_tld', '') or ''
                    info['continent'] = data.get('continent_code', '') or ''
                    info['eu'] = data.get('is_eu', False) or ''
                    currency_data = data.get('currency', '')
                    if isinstance(currency_data, dict):
                        info['currency'] = currency_data.get('code', '')
                    else:
                        info['currency'] = str(currency_data)

                    # Ensure country_area is string, not dict
                    country_area_data = data.get('country_area', '')
                    if isinstance(country_area_data, dict):
                        info['country_area'] = ''
                    else:
                        info['country_area'] = str(country_area_data)

                    # Ensure postal_code is string, not dict
                    postal_code_data = data.get('postal_code', '')
                    if isinstance(postal_code_data, dict):
                        info['postal_code'] = ''
                    else:
                        info['postal_code'] = str(postal_code_data)

                    # Ensure country_population is string, not dict
                    country_population_data = data.get('country_population', '')
                    if isinstance(country_population_data, dict):
                        info['country_population'] = ''
                    else:
                        info['country_population'] = str(country_population_data)

                    # Ensure eu is string
                    eu_data = data.get('is_eu', '')
                    if isinstance(eu_data, bool):
                        info['eu'] = str(eu_data)
                    else:
                        info['eu'] = str(eu_data) if eu_data else ''

                    # Ensure utc_offset is string
                    timezone_data = data.get('time_zone', '')
                    if isinstance(timezone_data, dict):
                        info['utc_offset'] = timezone_data.get('offset', '')
                    else:
                        info['utc_offset'] = str(timezone_data) if timezone_data else ''

                    # Add debug log for full API response
                    import json
                    logging.debug(f"Full API response for IP {ip}: {json.dumps(data)}")

                    # Check for incomplete data
                    required_fields = ['city', 'region', 'country_name', 'latitude', 'longitude', 'asn', 'org']
                    missing_or_unknown = False
                    for field in required_fields:
                        value = data.get(field)
                        if not value or (isinstance(value, str) and value.strip().lower() == 'unknown'):
                            missing_or_unknown = True
                            break
                    if missing_or_unknown:
                        logging.warning(f"❌ Incomplete geodata for IP {ip}: {data}")
                    else:
                        summary = f"✅ Geolocation success: {data.get('city', '')}, {data.get('region', '')}, {data.get('org', '')}"
                        logging.info(summary)
                        _ip_info_cache[ip] = info
                        return info
            except requests.exceptions.RequestException as e:
                logging.error(f"Request failed: {e}")
            if attempt == 0:
                time.sleep(1)  # Wait before retry
        # Fallback to ipinfo.io API
        response = requests.get(f'https://ipinfo.io/{ip}/json')
        if response.status_code == 200:
            data = response.json()
            info['country'] = data.get('country', info['country'])
            city_region = data.get('city', '') + ', ' + data.get('region', '')
            info['city'] = city_region.strip(', ') if city_region.strip(', ') else info['city']
            info['hostname'] = data.get('hostname', info['hostname'])
            info['isp'] = data.get('org', info['isp'])
            loc = data.get('loc', '')
            if loc:
                lat_long = loc.split(',')
                if len(lat_long) == 2:
                    info['latitude'] = lat_long[0]
                    info['longitude'] = lat_long[1]
            info['region'] = data.get('region', info['region'])
            info['region_code'] = data.get('region_code', info['region_code'])
            info['postal_code'] = data.get('postal', info['postal_code'])
            info['utc_offset'] = data.get('timezone', info['utc_offset'])
            info['country_iso_code'] = data.get('country', info['country_iso_code'])
            info['capital'] = data.get('country_capital', info['capital'])
            info['tld'] = data.get('country_tld', info['tld'])
            info['continent'] = data.get('continent_code', info['continent'])
            info['eu'] = data.get('in_eu', info['eu'])
            info['currency'] = data.get('currency', info['currency'])
            info['country_area'] = data.get('country_area', info['country_area'])
            info['country_population'] = data.get('country_population', info['country_population'])
        elif response.status_code == 429:
            logging.error(f"API quota exceeded for ipinfo.io on IP {ip}")
        # Additional fallback to ipgeolocation.io API for better city accuracy.
        if info['city'] == 'Unknown' or info['city'] == '':
            if API_KEY:
                response = requests.get(f'https://api.ipgeolocation.io/ipgeo?apiKey={API_KEY}&ip={ip}&fields=city,country_name,isp,hostname,latitude,longitude,region,region_code,postal,timezone,country_code,country_capital,country_tld,continent_code,in_eu,currency,country_area,country_population,asn')
                if response.status_code == 200:
                    data = response.json()
                    info['country'] = data.get('country_name', info['country'])
                    info['city'] = data.get('city', info['city'])
                    info['region'] = data.get('region', info['region'])
                    info['region_code'] = data.get('region_code', info['region_code'])
                    info['postal_code'] = data.get('postal', info['postal_code'])
                    info['network'] = data.get('org', info['network'])
                    info['asn'] = data.get('asn', info['asn'])
                    info['hostname'] = data.get('hostname', info['hostname'])
                    info['isp'] = data.get('isp', info['isp'])
                    info['latitude'] = data.get('latitude', info['latitude'])
                    info['longitude'] = data.get('longitude', info['longitude'])
                    info['utc_offset'] = data.get('timezone', info['utc_offset'])
                    info['country_iso_code'] = data.get('country_code', info['country_iso_code'])
                    info['capital'] = data.get('country_capital', info['capital'])
                    info['tld'] = data.get('country_tld', info['tld'])
                    info['continent'] = data.get('continent_code', info['continent'])
                    info['eu'] = data.get('in_eu', info['eu'])
                    info['currency'] = data.get('currency', info['currency'])
                    info['country_area'] = data.get('country_area', info['country_area'])
                    info['country_population'] = data.get('country_population', info['country_population'])
                    info['asn'] = data.get('asn', info['asn'])
                elif response.status_code == 429:
                    logging.error(f"API quota exceeded for ipgeolocation.io on IP {ip}")
            else:
                logging.error("Skipping ipgeolocation.io API call due to missing API key.")
        _ip_info_cache[ip] = info
    except Exception as e:
        logging.error(f"Error fetching IP info for {ip}: {e}")
    return info

# Add error handling around DB insertion in track route
# Removed duplicate track route definition to fix endpoint overwrite error
def track(short_id):
    urlmap = URLMap.query.filter_by(short_id=short_id).first_or_404()
    ip = get_client_ip()
    ua_string = request.headers.get('User-Agent', '')
    ua = user_agents.parse(ua_string)
    ip_info = get_ip_info(ip)
    try:
        visit = Visit(
            urlmap_id=urlmap.id,
            ip_address=ip,
            user_agent=ua_string,
            browser=f"{ua.browser.family} {ua.browser.version_string}",
            os=f"{ua.os.family} {ua.os.version_string}",
            referrer=request.referrer or '',
            country=ip_info['country'],
            city=ip_info['city'],
            region=ip_info.get('region', ''),
            region_code=ip_info.get('region_code', ''),
            postal_code=ip_info.get('postal_code', ''),
            utc_offset=ip_info.get('utc_offset', ''),
            network=ip_info.get('network', ''),
            asn=ip_info.get('asn', ''),
            country_iso_code=ip_info.get('country_iso_code', ''),
            capital=ip_info.get('capital', ''),
            tld=ip_info.get('tld', ''),
            continent=ip_info.get('continent', ''),
            eu=ip_info.get('eu', ''),
            currency=ip_info.get('currency', ''),
            country_area=ip_info.get('country_area', ''),
            country_population=ip_info.get('country_population', ''),
            latitude=ip_info['latitude'],
            longitude=ip_info['longitude'],
            hostname=ip_info['hostname'],
            isp=ip_info['isp']
        )
        db.session.add(visit)
        db.session.commit()
    except Exception as e:
        logging.error(f"Error inserting visit record: {e}")
        db.session.rollback()
    return render_template('track.html', short_id=short_id)

def get_client_ip():
    # Prefer X-Forwarded-For header for real client IP (may contain multiple IPs)
    x_forwarded_for = request.headers.get('X-Forwarded-For', '')
    if x_forwarded_for:
        # X-Forwarded-For can contain multiple IPs, take the first public IP (IPv4 or IPv6)
        ips = [ip.strip() for ip in x_forwarded_for.split(',')]
        for ip in ips:
            # Skip private and localhost IPs
            if not (ip.startswith('10.') or ip.startswith('192.168.') or ip.startswith('172.') or ip == '127.0.0.1' or ip == '::1'):
                return ip
        # If no public IP found, fallback to first IP
        return ips[0]
    else:
        ip = request.remote_addr
    return ip

# Routes
@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        original_url = request.form.get('original_url')
        if not original_url:
            return render_template('index.html', error='Please enter a URL.')
        # Check if URL already shortened
        urlmap = URLMap.query.filter_by(original_url=original_url).first()
        if urlmap is None:
            short_id = generate_short_id()
            while URLMap.query.filter_by(short_id=short_id).first() is not None:
                short_id = generate_short_id()
            urlmap = URLMap(original_url=original_url, short_id=short_id)
            db.session.add(urlmap)
            db.session.commit()
        return render_template('index.html', short_url=url_for('track', short_id=urlmap.short_id, _external=True))
    return render_template('index.html')

@app.route('/track/<short_id>')
def track(short_id):
    urlmap = URLMap.query.filter_by(short_id=short_id).first_or_404()
    ip = get_client_ip()
    ua_string = request.headers.get('User-Agent', '')
    ua = user_agents.parse(ua_string)
    ip_info = get_ip_info(ip)
    try:
        visit = Visit(
            urlmap_id=urlmap.id,
            ip_address=ip,
            user_agent=ua_string,
            browser=f"{ua.browser.family} {ua.browser.version_string}",
            os=f"{ua.os.family} {ua.os.version_string}",
            referrer=request.referrer or '',
            country=ip_info['country'],
            city=ip_info['city'],
            region=ip_info.get('region', ''),
            region_code=ip_info.get('region_code', ''),
            postal_code=ip_info.get('postal_code', ''),
            utc_offset=ip_info.get('utc_offset', ''),
            network=ip_info.get('network', ''),
            asn=ip_info.get('asn', ''),
            country_iso_code=ip_info.get('country_iso_code', ''),
            capital=ip_info.get('capital', ''),
            tld=ip_info.get('tld', ''),
            continent=ip_info.get('continent', ''),
            eu=ip_info.get('eu', ''),
            currency=ip_info.get('currency', ''),
            country_area=ip_info.get('country_area', ''),
            country_population=ip_info.get('country_population', ''),
            latitude=ip_info['latitude'],
            longitude=ip_info['longitude'],
            hostname=ip_info['hostname'],
            isp=ip_info['isp']
        )
        db.session.add(visit)
        db.session.commit()
    except Exception as e:
        logging.error(f"Error inserting visit record: {e}")
        db.session.rollback()
    return render_template('track.html', short_id=short_id)

@app.route('/track_data/<short_id>', methods=['POST'])
def track_data(short_id):
    urlmap = URLMap.query.filter_by(short_id=short_id).first_or_404()
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data provided'}), 400

    # Find the latest visit for this URL and update with advanced data
    visit = Visit.query.filter_by(urlmap_id=urlmap.id).order_by(Visit.timestamp.desc()).first()
    if not visit:
        return jsonify({'error': 'No visit found to update'}), 404

    visit.screen_size = data.get('screen_size')
    visit.color_scheme = data.get('color_scheme')
    visit.hdr_screen = data.get('hdr_screen')
    visit.gpu = data.get('gpu')
    visit.platform = data.get('platform')
    visit.timezone = data.get('timezone')
    visit.user_time = data.get('user_time')
    visit.language = data.get('language')
    visit.incognito = data.get('incognito')
    visit.ad_blocker = data.get('ad_blocker')
    visit.orientation = data.get('orientation')

    # Update city, country, hostname, ISP, latitude, longitude and other metadata always to ensure latest data
    try:
        ip = visit.ip_address
        ip_info = get_ip_info(ip)

        # Convert dict fields to strings if necessary
        def safe_str(value):
            if isinstance(value, dict):
                return str(value)
            if value is None:
                return ''
            return str(value)

        visit.country = safe_str(ip_info.get('country', ''))
        visit.city = safe_str(ip_info.get('city', ''))
        visit.region = safe_str(ip_info.get('region', ''))
        visit.region_code = safe_str(ip_info.get('region_code', ''))
        visit.postal_code = safe_str(ip_info.get('postal_code', ''))
        visit.utc_offset = safe_str(ip_info.get('utc_offset', ''))
        visit.network = safe_str(ip_info.get('network', ''))
        visit.asn = safe_str(ip_info.get('asn', ''))
        visit.country_iso_code = safe_str(ip_info.get('country_iso_code', ''))
        visit.capital = safe_str(ip_info.get('capital', ''))
        visit.tld = safe_str(ip_info.get('tld', ''))
        visit.continent = safe_str(ip_info.get('continent', ''))
        visit.eu = safe_str(ip_info.get('eu', ''))
        visit.currency = safe_str(ip_info.get('currency', ''))
        visit.country_area = safe_str(ip_info.get('country_area', ''))
        visit.country_population = safe_str(ip_info.get('country_population', ''))
        visit.hostname = safe_str(ip_info.get('hostname', ''))
        visit.isp = safe_str(ip_info.get('isp', ''))
        visit.latitude = safe_str(ip_info.get('latitude', ''))
        visit.longitude = safe_str(ip_info.get('longitude', ''))
    except Exception as e:
        logging.error(f"Error updating visit with IP info: {e}")

    db.session.commit()
    return jsonify({'status': 'success'})

@app.route('/track_redirect/<short_id>')
def track_redirect(short_id):
    urlmap = URLMap.query.filter_by(short_id=short_id).first_or_404()
    return redirect(urlmap.original_url)

@app.route('/stats/<short_id>')
def stats(short_id):
    urlmap = URLMap.query.filter_by(short_id=short_id).first_or_404()
    visits = Visit.query.filter_by(urlmap_id=urlmap.id).order_by(Visit.timestamp.desc()).all()
    return render_template('stats.html', urlmap=urlmap, visits=visits)

@app.route('/pixel/<short_id>.png')
def pixel(short_id):
    urlmap = URLMap.query.filter_by(short_id=short_id).first_or_404()
    ip = get_client_ip()
    ua_string = request.headers.get('User-Agent', '')
    ua = user_agents.parse(ua_string)
    ip_info = get_ip_info(ip)
    visit = Visit(
        urlmap_id=urlmap.id,
        ip_address=ip,
        user_agent=ua_string,
        browser=f"{ua.browser.family} {ua.browser.version_string}",
        os=f"{ua.os.family} {ua.os.version_string}",
        referrer=request.referrer or '',
        country=ip_info['country'],
        city=ip_info['city'],
        hostname=ip_info['hostname'],
        isp=ip_info['isp']
    )
    db.session.add(visit)
    db.session.commit()
    # Return a 1x1 transparent PNG
    pixel_data = b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01' \
                 b'\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89' \
                 b'\x00\x00\x00\nIDATx\x9cc`\x00\x00\x00\x02\x00\x01' \
                 b'\xe2!\xbc\x33\x00\x00\x00\x00IEND\xaeB`\x82'
    return app.response_class(pixel_data, mimetype='image/png')

if __name__ == '__main__':
    with app.app_context():
        # Temporary: create tables on startup for ephemeral DB (no data persistence)
        db.create_all()
        print("Tables created successfully. This is a temporary setup; data will not persist across deploys.")
    app.run(debug=True)

# Temporary fix for Render.com deployment to create tables on startup
# (This block is already inside the main block, so this line is redundant and removed)
