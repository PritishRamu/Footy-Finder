import os
import sqlite3
from flask import Flask, render_template, request, redirect, session, jsonify,url_for,g,flash
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash
import requests
import json
import re
from flask_login import login_required, current_user
from functools import wraps
from geopy.distance import geodesic
import logging
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer

logging.basicConfig(level=logging.INFO)


load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY")
GOOGLE_MAPS_API_KEY = os.getenv("GOOGLE_MAPS_API_KEY")
GEOCODING_API_KEY = os.getenv("GEOCODING_API_KEY")
DEFAULT_LAT_LNG = (51.5074, -0.1278)  # London
# Mail Configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')

# This defines the 'mail' object
mail = Mail(app)

# This defines the 'get_reset_token' function
def get_reset_token(user_id):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    return serializer.dumps(user_id, salt='password-reset-salt')

# You will need this function for the next step
def verify_reset_token(token, max_age=1800):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
        user_id = serializer.loads(token, salt='password-reset-salt', max_age=max_age)
    except:
        return None
    return user_id


# Initialize database
def init_db():
    conn = sqlite3.connect('footy.db')
    # conn.row_factory=sqlite3.Row
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                     username TEXT PRIMARY KEY,
                     password TEXT NOT NULL
                 )''')
    c.execute(''' CREATE TABLE IF NOT EXISTS favorites (
                       username TEXT,
                       club_name TEXT,
                       address TEXT,
                       rating TEXT,
                       phone TEXT,
                       website TEXT,
                       lat REAL,
                       lng REAL,
                       PRIMARY KEY (username, club_name),
                       FOREIGN KEY (username) REFERENCES users(username)
                 )''')
    

    c.execute('''
    CREATE TABLE IF NOT EXISTS reviews (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        place_id TEXT,
        review TEXT,
        rating INTEGER,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )
''')
    conn.commit()
    conn.close()

init_db()

import sqlite3

def get_db_connection():
    conn = sqlite3.connect('footyfinder.db')  # Make sure this matches your actual DB name
    conn.row_factory = sqlite3.Row  # This makes returned rows behave like dicts
    return conn

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'success': False, 'error': 'Login required'}), 401
        return f(*args, **kwargs)
    return decorated_function

DATABASE = 'footy.db'

def get_db():
    db = sqlite3.connect('footy.db')
    db.row_factory = sqlite3.Row
    return db


def close_db(e=None):
    """Close the database connection."""
    db = getattr(g, 'db', None)
    if db is not None:
        db.close()





def parse_dms(dms_str):
    """
    Parse coordinates in DMS (Degrees, Minutes, Seconds) format to decimal degrees.
    Example input: 51°36'17.1"N 0°04'05.1"W
    """
    regex = re.compile(r"""(?P<lat_deg>\d+)°(?P<lat_min>\d+)'(?P<lat_sec>[\d.]+)"(?P<lat_dir>[NS])
                             \s+
                             (?P<lng_deg>\d+)°(?P<lng_min>\d+)'(?P<lng_sec>[\d.]+)"(?P<lng_dir>[EW])""", re.VERBOSE)
    match = regex.match(dms_str.strip())

    if not match:
        return None

    def dms_to_dd(deg, minutes, sec, direction):
        dd = float(deg) + float(minutes)/60 + float(sec)/3600
        if direction in ['S', 'W']:
            dd *= -1
        return dd

    lat = dms_to_dd(match['lat_deg'], match['lat_min'], match['lat_sec'], match['lat_dir'])
    lng = dms_to_dd(match['lng_deg'], match['lng_min'], match['lng_sec'], match['lng_dir'])
    return lat, lng

@app.route('/')
def root():
    return redirect('/login')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Use the get_db function for a reliable connection
        db = get_db() 
        user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        
        # Access data by column NAME, not index number
        if user and check_password_hash(user['password'], password): 
            session.clear() 
            session['user_id'] = user['id']
            session['username'] = user['username']
            return redirect('/home')
        else:
            return render_template('login.html', error='Invalid username or password')
            
    return render_template('login.html')

# In app.py
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']      # GET EMAIL FROM FORM
        password = request.form['password']
        
        db = get_db()
        
        if db.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone() is not None:
            return render_template('register.html', error='Username already exists')

        hashed_password = generate_password_hash(password)
        
        # SAVE EMAIL TO THE DATABASE
        db.execute('INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
                   (username, email, hashed_password))
        db.commit()
        
        flash('You have been registered successfully! Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/home')
def home():
    if 'username' not in session:
        return redirect('/login')
    return render_template('index.html', api_key=GOOGLE_MAPS_API_KEY)

@app.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('user_id',None)
    return redirect('/login')





PROMINENT_CLUBS= {
    # Premier League (20 Clubs)
    "Arsenal": "Arsenal",
    "Aston Villa": "Villa",
    "Bournemouth": "Bournemouth",
    "Brentford": "Brentford",
    "Brighton & Hove Albion": "Brighton",
    "Burnley": "Burnley",
    "Chelsea": "Chelsea",
    "Crystal Palace": "Palace",
    "Everton": "Everton",
    "Fulham": "Fulham",
    "Leeds United": "Leeds",
    "Liverpool": "Liverpool",
    "Manchester City": "Man City",
    "Manchester United": "Man United",
    "Newcastle United": "Newcastle",
    "Nottingham Forest": "Forest",
    "Tottenham Hotspur": "Spurs",
    "West Ham United": "West Ham United",
    "Wolverhampton Wanderers": "Wolves",
    "Luton Town": "Luton",

    # EFL Championship (24 Clubs)
    "Birmingham City": "Birmingham",
    "Blackburn Rovers": "Blackburn",
    "Bristol City": "Bristol City",
    "Cardiff City": "Cardiff",
    "Coventry City": "Coventry",
    "Derby County": "Derby",
    "Huddersfield Town": "Huddersfield",
    "Hull City": "Hull",
    "Ipswich Town": "Ipswich",
    "Leicester City": "Leicester",
    "Middlesbrough": "Boro",
    "Millwall": "Millwall",
    "Norwich City": "Norwich",
    "Oxford United": "Oxford",
    "Peterborough United": "Peterborough",
    "Portsmouth": "Portsmouth",
    "Preston North End": "PNE",
    "Queens Park Rangers": "QPR",
    "Sheffield United": "Sheff Utd",
    "Southampton": "Southampton",
    "Stoke City": "Stoke",
    "Sunderland": "Sunderland",
    "Swansea City": "Swansea",
    "Watford": "Watford",

    # EFL League One (24 Clubs)
    "Barnsley": "Barnsley",
    "Blackpool": "Blackpool",
    "Bolton Wanderers": "Bolton",
    "Bristol Rovers": "Bristol Rovers",
    "Burton Albion": "Burton",
    "Cambridge United": "Cambridge",
    "Charlton Athletic": "Charlton",
    "Crawley Town": "Crawley",
    "Exeter City": "Exeter",
    "Leyton Orient": "Leyton Orient",
    "Lincoln City": "Lincoln",
    "Mansfield Town": "Mansfield",

    "Milton Keynes Dons": "MK Dons",
    "Northampton Town": "Northampton",
    "Reading": "Reading",
    "Rotherham United": "Rotherham",
    "Shrewsbury Town": "Shrewsbury",
    "Stevenage": "Stevenage",
    "Stockport County": "Stockport",
    "West Bromwich Albion": "WBA",
    "Wigan Athletic": "Wigan",
    "Wrexham": "Wrexham",
    "Wycombe Wanderers": "Wycombe Wanderers",
    "Plymouth Argyle": "Plymouth",

    # EFL League Two (24 Clubs)
    "Accrington Stanley": "Accrington",
    "AFC Wimbledon": "AFC Wimbledon",
    "Barrow": "Barrow",
    "Bradford City": "Bradford",
    "Bromley": "Bromley",
    "Carlisle United": "Carlisle",
    "Cheltenham Town": "Cheltenham",
    "Chesterfield": "Chesterfield",
    "Colchester United": "Colchester",
    "Crewe Alexandra": "Crewe",
    "Doncaster Rovers": "Doncaster",
    "Fleetwood Town": "Fleetwood",
    "Forest Green Rovers": "Forest Green",
    "Gillingham": "Gillingham",
    "Grimsby Town": "Grimsby",
    "Harrogate Town": "Harrogate",
    "Morecambe": "Morecambe",
    "Newport County": "Newport",
    "Notts County": "Notts County",
    "Oldham Athletic": "Oldham",
    "Port Vale": "Port Vale",
    "Salford City": "Salford",

    "Tranmere Rovers": "Tranmere",
    "Walsall": "Walsall"
}

@app.route('/get_clubs', methods=['POST'])
def get_clubs():
    data = request.get_json()

    location = data.get('location')
    lat = data.get('lat')
    lng = data.get('lng')

    DEFAULT_LAT_LNG = (51.5074, -0.1278)

    if not (location or (lat and lng)):
        return jsonify({'error': 'Location required'}), 400

    # --- Handle location input (Your existing code is perfect here) ---
    if location:
        dms_coords = parse_dms(location)
        if dms_coords:
            lat, lng = dms_coords
        else:
            geocode_url = f'https://maps.googleapis.com/maps/api/geocode/json?address={location}&key={GOOGLE_MAPS_API_KEY}'
            try:
                geocode_response = requests.get(geocode_url).json()
            except requests.RequestException:
                return jsonify({'error': 'Failed to connect to geocoding service'}), 500

            if not geocode_response.get('results'):
                return jsonify({'error': 'Invalid location'}), 400

            lat_lng = geocode_response['results'][0]['geometry']['location']
            lat, lng = lat_lng['lat'], lat_lng['lng']
    else:
        try:
            lat = float(lat)
            lng = float(lng)
        except (TypeError, ValueError):
            return jsonify({'error': 'Invalid coordinates'}), 400

    # --- Check if location is in the UK (Your existing code is perfect here) ---
    reverse_geocode_url = f'https://maps.googleapis.com/maps/api/geocode/json?latlng={lat},{lng}&key={GOOGLE_MAPS_API_KEY}'
    try:
        reverse_geocode_response = requests.get(reverse_geocode_url).json()
    except requests.RequestException:
        return jsonify({'error': 'Failed to reverse geocode'}), 500

    if not reverse_geocode_response.get('results'):
        return jsonify({'error': 'Unable to reverse geocode coordinates'}), 400

    country = None
    for comp in reverse_geocode_response['results'][0]['address_components']:
        if 'country' in comp['types']:
            country = comp['long_name']
            break

    if country != "United Kingdom":
        return jsonify({'error': 'not_in_uk', 'lat': DEFAULT_LAT_LNG[0], 'lng': DEFAULT_LAT_LNG[1]})

    # --- Search for nearby football clubs (Your existing code is perfect here) ---
    places_url = (
        f'https://maps.googleapis.com/maps/api/place/nearbysearch/json'
        f'?location={lat},{lng}&radius=10000&keyword=football club&key={GOOGLE_MAPS_API_KEY}'
    )
    try:
        places_response = requests.get(places_url).json()
    except requests.RequestException:
        return jsonify({'error': 'Failed to search nearby places'}), 500

    raw_results = places_response.get('results', [])
    clubs = []
    
    # --- THIS IS THE MAIN MODIFIED LOOP ---
    for place in raw_results:
        club_data = {
            'name': place.get('name', ''),
            'address': place.get('vicinity', ''),
            'rating': place.get('rating', 'N/A'),
            'location': place['geometry']['location'],
            'place_id': place.get('place_id')
        }

        # Fetch phone number and website
        details_url = (
            f'https://maps.googleapis.com/maps/api/place/details/json'
            f'?place_id={club_data["place_id"]}&fields=formatted_phone_number,website&key={GOOGLE_MAPS_API_KEY}'
        )
        try:
            details_response = requests.get(details_url).json()
            details = details_response.get('result', {})
        except requests.RequestException:
            details = {}

        club_data['phone'] = details.get('formatted_phone_number', 'N/A')
        club_data['website'] = details.get('website', 'N/A')
        
        # --- NEW: CHECK FOR PROMINENT CLUB AND GET NEXT MATCH ---
        for team_name in PROMINENT_CLUBS:
            if team_name in club_data['name']:
                club_data['next_match'] = get_next_match(team_name)
                break  # Stop checking once a match is found

        clubs.append(club_data)

    logging.info(f"Found {len(clubs)} clubs near ({lat}, {lng})")
    return jsonify({'clubs': clubs, 'lat': lat, 'lng': lng})
@app.route('/add_favorite', methods=['POST'])
def add_favorite():
    if 'user_id' not in session:  # Check if the user is logged in
        return jsonify({'error': 'Not logged in'}), 403

    data = request.get_json()
    club = data.get('club')

    if not club:
        return jsonify({'error': 'Invalid data: Missing club data'}), 400

    place_id = club.get('place_id')
    club_name = club.get('club_name')
    address = club.get('address')
    rating = club.get('rating')
    phone = club.get('phone')
    website = club.get('website')
    lat = club.get('lat')
    lng = club.get('lng')

    if not all([place_id, club_name, address, lat, lng]):
        return jsonify({'error': 'Invalid data: Missing required fields'}), 400

    try:
        conn = sqlite3.connect('footy.db')
        c = conn.cursor()
        c.execute('''INSERT OR IGNORE INTO favorites 
                       (user_id, club_name, address, rating, phone, website, lat, lng, place_id) 
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                  (
                      session['user_id'],
                      club_name,
                      address,
                      rating,
                      phone,
                      website,
                      lat,
                      lng,
                      place_id
                  ))
        conn.commit()
        conn.close()
        return jsonify({'success': True, 'message': f'{club_name} added to favourites!'})
    except Exception as e:
        return jsonify({'error': f'Database error: {str(e)}'}), 500








@app.route('/get_favorites', methods=['GET'])
@login_required
def get_favorites():
    print("Fetching favourites for user:", session['user_id'])
    db = get_db()
    favorites = db.execute(
        '''SELECT club_name, address, rating, phone, website, lat, lng, place_id 
           FROM favorites WHERE user_id = ?''',
        (session['user_id'],)
    ).fetchall()

    print("Fetched Rows:",favorites)

    clubs = [{
        'name': row['club_name'],
        'address': row['address'],
        'rating': row['rating'],
        'phone': row['phone'],
        'website': row['website'],
        'location': {'lat': row['lat'], 'lng': row['lng']},
        'place_id': row['place_id']
    } for row in favorites]

    return jsonify({'clubs': clubs})











@app.route('/remove_favorite', methods=['POST'])
def remove_favorite():
    if 'user_id' not in session:  # Assuming you store user_id in session
        return jsonify({'error': 'Not logged in'}), 403

    data = request.get_json()
    
    if not data:
        return jsonify({'error': 'No data received'}), 400

    club = data.get('club')
    
    if not club:
        return jsonify({'error': 'Invalid data, club missing'}), 400

    place_id = club.get('place_id')
    if not place_id:
        return jsonify({'error': 'Missing place_id'}), 400

    try:
        # Log the received data for debugging purposes
        print(f"Removing favourite for place_id: {place_id}, user_id: {session['user_id']}")

        conn = sqlite3.connect('footy.db')
        c = conn.cursor()
        c.execute('''DELETE FROM favorites WHERE user_id=? AND place_id=?''',
                  (session['user_id'], place_id))
        conn.commit()
        conn.close()

        return jsonify({'success': True, 'message': 'Favourite removed successfully'})
    except Exception as e:
        # Log the exception for debugging
        print(f"Database error: {str(e)}")
        return jsonify({'error': f'Database error: {str(e)}'}), 500






@app.route('/submit_review', methods=['POST'])
def submit_review():
    data = request.get_json()
    user_id = session.get('user_id')  # Optional: if login is implemented
    place_id = data.get('place_id')
    review = data.get('comment')  # 🔁 Use 'comment' to match frontend
    rating = data.get('rating')

    if not place_id or not review or rating is None:
        return jsonify({'success': False, 'error': 'Missing required fields'}), 400

    conn = sqlite3.connect('footy.db')
    c = conn.cursor()
    
    if user_id:
        c.execute(
            'INSERT INTO reviews (user_id, place_id, review, rating, timestamp) VALUES (?, ?, ?, ?, datetime("now"))',
            (user_id, place_id, review, rating)
        )
    else:
        c.execute(
            'INSERT INTO reviews (place_id, review, rating, timestamp) VALUES (?, ?, ?, datetime("now"))',
            (place_id, review, rating)
        )
    
    conn.commit()
    conn.close()

    return jsonify({'success': True, 'message': 'Review submitted successfully'})



@app.route('/get_reviews/<place_id>')
def get_reviews(place_id):
    conn = sqlite3.connect('footy.db')
    c = conn.cursor()
    
    # Join users table to get usernames for each review
    c.execute('''
        SELECT u.username, r.rating, r.review, r.timestamp
        FROM reviews r
        JOIN users u ON r.user_id = u.id
        WHERE r.place_id = ?
        ORDER BY r.timestamp DESC
    ''', (place_id,))
    
    rows = c.fetchall()
    conn.close()

    formatted = [
        {
            'username': row[0],
            'rating': row[1],
            'review': row[2],
            'timestamp': row[3]
        }
        for row in rows
    ]
    return jsonify({'reviews': formatted})

# @app.route('/reset_favorites')
# def reset_favorites():
#     db = get_db()
#     db.execute('DROP TABLE IF EXISTS favorites')
#     db.execute('''
#         CREATE TABLE favorites (
#             id INTEGER PRIMARY KEY AUTOINCREMENT,
#             user_id INTEGER NOT NULL,
#             place_id TEXT NOT NULL,
#             club_name TEXT,
#             FOREIGN KEY (user_id) REFERENCES users(id)
#         )
#     ''')
#     db.commit()
#     return "Favorites table reset and recreated with user_id!"


@app.route('/search_clubs', methods=['POST'])
def search_clubs():
    # Get the search filters from the request
    data = request.get_json()
    query = data.get('query', '').strip()
    rating_filter = data.get('rating')
    distance_filter = data.get('distance')

    # Set the user's location if they entered one
    user_location = None
    if query:
        user_location = get_coordinates_from_address(query)  # You can use Google Maps API here

    # Prepare the SQL query for searching clubs
    conn = sqlite3.connect('footy.db')
    conn.row_factory=sqlite3.Row
    c = conn.cursor()
    sql_query = "SELECT * FROM favorites WHERE 1=1"
    
    params = []
    
    # Apply rating filter if specified
    if rating_filter:
        sql_query += " AND rating >= ?"
        params.append(rating_filter)
    
    # Apply location and distance filter if specified
    if user_location and distance_filter:
        sql_query += " AND lat IS NOT NULL AND lng IS NOT NULL"
        
    # Execute the query
    c.execute(sql_query, params)
    clubs = c.fetchall()
    
    # Calculate distances if location filtering is applied
    if user_location and distance_filter:
        clubs = [
            club for club in clubs
            if geodesic(user_location, (club['lat'], club['lng'])).km <= distance_filter
        ]
    
    # Format clubs for the response
    club_list = []
    for club in clubs:
        club_list.append({
            'name': club['club_name'],
            'address': club['address'],
            'rating': club['rating'],
            'phone': club['phone'],
            'website': club['website'],
            'location': {'lat': club['lat'], 'lng': club['lng']},
            'place_id': club['place_id']
        })

    conn.close()
    
    return jsonify({'clubs': club_list,'user_location':{'lat':user_location[0],'lng':user_location[1]} if user_location else None})



@app.route('/dashboard')
@login_required
def dashboard():
    db=get_db()
    favorites=db.execute(
        '''SELECT club_name, address, rating, phone, website
           FROM favorites WHERE user_id = ?''',
        (session['user_id'],)
    ).fetchall()
    
    return render_template('dashboard.html',favorites=favorites)







def get_coordinates_from_address(address):
    """Get coordinates from decimal degrees, DMS format, or place name."""

    # 1. Check if it's Decimal Degrees
    decimal_regex = r'^-?\d+(\.\d+)?\s*,\s*-?\d+(\.\d+)?$'
    if re.match(decimal_regex, address.strip()):
        lat, lng = map(float, address.strip().split(','))
        return lat, lng

    # 2. Check if it's DMS (Degrees Minutes Seconds)
    coords = parse_dms(address)
    if coords:
        return coords

    # 3. Otherwise, use Google Geocoding API for place names
    # GEOCODING_API_KEY = "YOUR_GOOGLE_API_KEY"  # replace this
    url = "https://maps.googleapis.com/maps/api/geocode/json"
    params = {
        "address": address,
        "key": GEOCODING_API_KEY
    }

    response = requests.get(url, params=params)
    if response.status_code == 200:
        data = response.json()
        if data['status'] == 'OK':
            location = data['results'][0]['geometry']['location']
            return location['lat'], location['lng']

    # If everything fails
    return None




def get_next_match(team_name):
    try:
        # Step 1: Get the Team ID from the Team Name
        search_url = f"https://www.thesportsdb.com/api/v1/json/123/searchteams.php?t={team_name}"
        search_response = requests.get(search_url).json()
        
        if not search_response or not search_response.get('teams'):
            return None
        
        team_id = search_response['teams'][0]['idTeam']

        # Step 2: Get the Next Match Using the Team ID
        events_url = f"https://www.thesportsdb.com/api/v1/json/123/eventsnext.php?id={team_id}"
        events_response = requests.get(events_url).json()

        if not events_response or not events_response.get('events'):
            return None

        next_event = events_response['events'][0]

        # Step 3: Extract the details
        home_team = next_event['strHomeTeam']
        away_team = next_event['strAwayTeam']
        
        if team_name in home_team:
            status = "(H)"
            opponent_name = away_team
            opponent_logo = next_event['strAwayTeamBadge']
        else:
            status = "(A)"
            opponent_name = home_team
            opponent_logo = next_event['strHomeTeamBadge']

        # The original, simple time format
        return {
            "opponent": opponent_name,
            "competition": next_event['strLeague'],
            "time": f"{next_event['dateEvent']} at {next_event['strTimeLocal']}",
            "status": status,
            "opponent_logo": opponent_logo
        }
        
    except Exception as e:
        print(f"Error fetching match data for {team_name}: {e}")
        return None
    
# In app.py

@app.route('/request_reset', methods=['GET', 'POST'])
def request_password_reset():
    if request.method == 'POST':
        email = request.form['email']
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        
        if user:
            token = get_reset_token(user['id'])
            # 1. Create the reset link
            reset_link = url_for('reset_with_token', token=token, _external=True)
            
            # 2. Create the Message object
            msg = Message('Password Reset Request for Footy Finder',
                          sender=os.getenv('MAIL_USERNAME'),
                          recipients=[user['email']])
            
            # 3. Set the plain-text body (for fallback)
            msg.body = f'''To reset your password, visit the following link: {reset_link}
If you did not make this request, simply ignore this email.
'''
            # 4. Render the HTML template and set it as the html body
            msg.html = render_template('reset_email.html', link=reset_link)
            
            # 5. Send the email
            mail.send(msg)

            flash('An email has been sent with instructions to reset your password.', 'info')
            return redirect(url_for('login'))
        else:
            flash('Email address not found.', 'warning')
            
    return render_template('request_reset.html')


@app.route('/reset/<token>', methods=['GET', 'POST'])
def reset_with_token(token):
    # Verify the token is valid and not expired
    user_id = verify_reset_token(token)
    if not user_id:
        flash('That is an invalid or expired token.', 'warning')
        return redirect(url_for('request_password_reset'))

    # If the form is submitted, update the password
    if request.method == 'POST':
        password = request.form['password']
        hashed_password = generate_password_hash(password)
        db = get_db()
        db.execute('UPDATE users SET password = ? WHERE id = ?', (hashed_password, user_id))
        db.commit()
        flash('Your password has been updated! You can now log in.', 'success')
        return redirect(url_for('login'))
        
    # If it's a GET request, just show the page
    return render_template('reset_with_token.html')










if __name__ == '__main__':
    app.run()