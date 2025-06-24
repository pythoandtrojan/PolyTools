#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import json
import re
import time
import subprocess
import logging
import random
from datetime import datetime
from typing import Dict, List, Optional, Any
import requests
from requests.exceptions import RequestException, Timeout, ConnectionError
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, Style, init
from bs4 import BeautifulSoup
from tqdm import tqdm # Para barra de progresso

# Initialize colorama for terminal colors
init(autoreset=True)

# Configure the logging system
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    handlers=[logging.StreamHandler(sys.stdout)])

# Global Configurations
class Config:
    RESULTS_FOLDER = "ErikNet_Results"
    REQUEST_TIMEOUT = 15 # Timeout for requests
    USER_AGENTS = [ # List of common User-Agents for rotation
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/103.0.1264.71",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.5 Safari/605.1.15",
        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0",
        "Mozilla/5.0 (Android 12; Mobile; rv:102.0) Gecko/102.0 Firefox/102.0",
        "Mozilla/5.0 (Linux; Android 10; Termux) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Mobile Safari/537.36 ErikNet/4.0",
    ]
    MAX_WORKERS = 15 # Max threads for parallel searches (adjust as needed)
    
    # Proxy settings - set these as environment variables
    HTTP_PROXY = os.getenv('HTTP_PROXY')
    HTTPS_PROXY = os.getenv('HTTPS_PROXY')
    SOCKS_PROXY = os.getenv('SOCKS_PROXY')

    PROXIES: Optional[Dict[str, str]] = {}
    if HTTP_PROXY:
        PROXIES['http'] = HTTP_PROXY
    if HTTPS_PROXY:
        PROXIES['https'] = HTTPS_PROXY
    if SOCKS_PROXY:
        PROXIES['http'] = SOCKS_PROXY
        PROXIES['https'] = SOCKS_PROXY
    
    # Create the results folder if it doesn't exist
    os.makedirs(RESULTS_FOLDER, exist_ok=True)

# ErikNet Banner
BANNER = r"""
███████░██░ ░██░███████░░    ██░      ░██░ ░██░██████░ ██    ██░███████░██████░
░░░██░░ ██░░░██░██  ░░      ██░░    ░██░ ░██░██  ░██ ██  ██░ ██░░░░  ██  ░██░
  ░██░  ███████░█████░░      ██░      ░██░ ░██░██████░ ████░   █████   ██████░░
  ░██░░ ██  ░██░██  ░░      ██░░░░  ░██░░░░██░██  ██░ ██░░██░ ██░░░   ██  ░██░░
  ░██░░ ██░░░██░███████░░    ███████ ░████████░██░░░██ ██░░ ██ ███████ ██  ░██░
    ░░░ ░░░ ░░░ ░░░░░░░      ░░░░░░░  ░░░░░░░░ ░░  ░░ ░░  ░░░ ░░░░░░░░░░░░░░░░
    ░ ░ ░     ░ ░  ░ ░      ░░  ░░  ░░░  ░░░  ░  ░  ░  ░░ ░░  ░    ░░    ░░
  ░ ░           ░  ░    ░  ░    ░  ░ ░    ░  ░    ░     ░  ░    ░  ░
  made in Brazil Big The god and Erik 16y Linux and termux  
"""

def clear_screen():
    """Clears the terminal screen."""
    os.system('cls' if os.name == 'nt' else 'clear')

def get_random_user_agent() -> str:
    """Returns a random User-Agent string from the predefined list."""
    return random.choice(Config.USER_AGENTS)

def execute_holehe(email: str) -> Dict[str, Any]:
    """
    Executes the Holehe tool to verify email existence across platforms (requires holehe installed).
    Returns a standardized dictionary with results.
    """
    logging.info(f"{Fore.BLUE}\nExecuting Holehe for email verification: {email}...{Style.RESET_ALL}")
    result_data = {'raw_output': None, 'error': None}
    try:
        process = subprocess.run(['holehe', email], capture_output=True, text=True, timeout=120)
        result_data['raw_output'] = process.stdout
        
        if process.returncode == 0:
            logging.info(f"{Fore.GREEN}\nResults from Holehe:\n{Style.RESET_ALL}{process.stdout}")
            
            file_name = f"holehe_results_{email.replace('@', '_').replace('.', '_')}.txt"
            file_path = os.path.join(Config.RESULTS_FOLDER, file_name)
            
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(process.stdout)
            
            logging.info(f"{Fore.GREEN}Holehe results saved to: {file_path}{Style.RESET_ALL}")
            return {'exists': True, 'method': 'External Tool (Holehe)', 'url': 'N/A', 'data': result_data}
        else:
            result_data['error'] = process.stderr
            logging.error(f"{Fore.RED}\nError executing Holehe:\n{Style.RESET_ALL}{process.stderr}")
            return {'exists': False, 'method': 'External Tool (Holehe)', 'url': 'N/A', 'data': result_data, 'error': result_data['error']}
    except FileNotFoundError:
        error_msg = "Holehe is not installed. Please install with: 'pip install holehe'"
        logging.error(f"{Fore.RED}\n{error_msg}{Style.RESET_ALL}")
        result_data['error'] = error_msg
        return {'exists': False, 'method': 'External Tool (Holehe)', 'url': 'N/A', 'data': result_data, 'error': result_data['error']}
    except Timeout:
        error_msg = f"Holehe timed out for {email}."
        logging.error(f"{Fore.RED}\nError: {error_msg}{Style.RESET_ALL}")
        result_data['error'] = error_msg
        return {'exists': False, 'method': 'External Tool (Holehe)', 'url': 'N/A', 'data': result_data, 'error': result_data['error']}
    except Exception as e:
        error_msg = f"Unexpected error executing Holehe: {str(e)}"
        logging.error(f"{Fore.RED}\n{error_msg}{Style.RESET_ALL}")
        result_data['error'] = error_msg
        return {'exists': False, 'method': 'External Tool (Holehe)', 'url': 'N/A', 'data': result_data, 'error': result_data['error']}

def verify_gmail_heuristic(email: str) -> Dict[str, Any]:
    """
    Attempts to verify the existence of a Gmail account using heuristics.
    WARNING: This is an UNOFFICIAL and unstable verification.
    It may result in false positives/negatives, be subject to changes by Google, or lead to blocks.
    """
    logging.info(f"{Fore.BLUE}Verifying Gmail (unofficial heuristic) for {email}...{Style.RESET_ALL}")
    session = requests.Session()
    headers = {"User-Agent": get_random_user_agent()}
    
    # Ensure proxies are used if configured
    session.proxies = Config.PROXIES if Config.PROXIES else {}

    try:
        # Attempt 1: Check for GX cookie on gxlu endpoint
        response1 = session.head(
            "https://mail.google.com/mail/gxlu",
            params={"email": email},
            timeout=Config.REQUEST_TIMEOUT,
            headers=headers
        )
        
        # Attempt 2: Set-cookie in the GET response of gxlu
        response2 = session.get(
            f"https://mail.google.com/mail/gxlu?email={email}",
            headers=headers,
            timeout=Config.REQUEST_TIMEOUT
        )
        
        # Attempt 3: Username availability during signup (JSON endpoint)
        # Note: This endpoint is more prone to being blocked or changed.
        signup_valid_status = 'N/A'
        try:
            # For this specific endpoint, Google might expect the username part only
            username_part = email.split('@')[0]
            signup_headers = {
                "Content-Type": "application/json", 
                "User-Agent": get_random_user_agent(),
                "Referer": "https://accounts.google.com/signup" # Add Referer for realism
            }
            response3 = session.post(
                "https://accounts.google.com/_/signup/usernameavailability",
                headers=signup_headers,
                json={"input_01": {"input": username_part, "first_name": "", "last_name": ""}},
                params={"hl": "en"}, # Using English for consistency
                timeout=Config.REQUEST_TIMEOUT
            )
            signup_valid_status = response3.json().get("input_01", {}).get("valid") is False if response3.status_code == 200 else 'N/A'
        except (RequestException, Timeout, json.JSONDecodeError) as e:
            logging.debug(f"Failed attempt 3 of Gmail verification for {email}: {e}")
            signup_valid_status = 'Error'

        exists = any([
            bool(response1.cookies.get("GX")),
            "set-cookie" in response2.headers,
            signup_valid_status is True
        ])

        return {'exists': exists, 'method': 'Gmail Heuristic', 'url': f"mailto:{email}", 'details': {
            'gx_cookie_detected': bool(response1.cookies.get("GX")),
            'set_cookie_header_detected': "set-cookie" in response2.headers,
            'username_unavailable_in_signup': signup_valid_status
        }}
    except Timeout:
        logging.warning(f"{Fore.YELLOW}Timeout on Gmail verification for {email}.{Style.RESET_ALL}")
        return {'exists': False, 'method': 'Gmail Heuristic', 'url': f"mailto:{email}", 'error': 'Timeout'}
    except RequestException as e:
        logging.warning(f"{Fore.YELLOW}Request error on Gmail verification for {email}: {str(e)}{Style.RESET_ALL}")
        return {'exists': False, 'method': 'Gmail Heuristic', 'url': f"mailto:{email}", 'error': str(e)}
    except Exception as e:
        logging.error(f"{Fore.RED}Unexpected error on Gmail verification for {email}: {str(e)}{Style.RESET_ALL}")
        return {'exists': False, 'method': 'Gmail Heuristic', 'url': f"mailto:{email}", 'error': str(e)}


def search_profiles(username: str) -> Dict[str, Any]:
    """
    Searches for user profiles across a vast list of social networks and platforms
    by checking common profile URLs.
    """
    results: Dict[str, Any] = {}
    
    # Dictionary of sites to be checked.
    # 'url': Profile URL, with '{username}' as placeholder.
    # 'method': Verification method ('Web Scraping', 'Public API', 'Status Check').
    # 'not_found_text': (Optional) List of lowercase texts that indicate the profile DOES NOT exist,
    #                   even if HTTP status is 200 (useful for "not found" profiles with 200 OK).
    # 'json_field': (Optional) Path to the real name field in a JSON response (e.g., 'data.name').
    # 'note': (Optional) Note about the difficulty or limitations of verification.
    sites = {
        # --- Popular Social Networks ---
        "Facebook": {"url": "https://www.facebook.com/{username}", "method": "Web Scraping", "not_found_text": ["página não encontrada", "content_owner_id", "não está disponível", "page not found", "error 404"]},
        "Instagram": {"url": "https://www.instagram.com/{username}/", "method": "Web Scraping", "not_found_text": ["esta página não está disponível", "page not found", "não foi possível encontrar esta página"]},
        "Twitter/X": {"url": "https://twitter.com/{username}", "method": "Web Scraping", "not_found_text": ["esta conta não existe", "essa conta não existe", "account suspended"]},
        "TikTok": {"url": "https://www.tiktok.com/@{username}", "method": "Web Scraping", "not_found_text": ["couldn't find this account", "this account is private"]},
        "Kwai": {"url": "https://www.kwai.com/@{username}", "method": "Web Scraping", "not_found_text": ["não existe", "not exist"]},
        "LinkedIn": {"url": "https://www.linkedin.com/in/{username}", "method": "Web Scraping", "not_found_text": ["this page doesn't exist", "página não existe"]},
        "Reddit": {"url": "https://www.reddit.com/user/{username}/about.json", "method": "Public API", "json_field": "data.name", "not_found_text": ['{"message": "not found", "error": 404}', "page not found"]},
        "Pinterest": {"url": "https://www.pinterest.com/{username}/", "method": "Web Scraping", "not_found_text": ["não podemos encontrar esta página", "page not found"]},
        "Snapchat (Story)": {"url": "https://story.snapchat.com/@{username}", "method": "Web Scraping", "not_found_text": ["not found"]},
        "Mastodon (Example .social)": {"url": "https://mastodon.social/@{username}", "method": "Web Scraping", "not_found_text": ["not found", "the page you were looking for doesn't exist"]},
        "Tumblr": {"url": "https://{username}.tumblr.com", "method": "Web Scraping", "not_found_text": ["whatever you were looking for doesn't exist", "there's nothing here", "404 not found"]},
        "Flickr": {"url": "https://www.flickr.com/people/{username}/", "method": "Web Scraping", "not_found_text": ["user not found", "page not found"]},
        "Imgur": {"url": "https://imgur.com/user/{username}", "method": "Web Scraping", "not_found_text": ["not found", "page not found"]},
        "DeviantArt": {"url": "https://www.deviantart.com/{username}/", "method": "Web Scraping", "not_found_text": ["page not found", "error 404"]},
        "Weibo (Not direct URL)": {"url": "N/A", "method": "Direct public API not available", "note": "Highly restricted for external searches. Requires API access."},
        "VK (Not direct URL)": {"url": "N/A", "method": "Direct public API not available", "note": "Highly restricted for external searches. Requires API access."},
        "Telegram (Public Channel/User)": {"url": "https://t.me/{username}", "method": "Web Scraping", "not_found_text": ["channel not found", "user not found"]},
        "WhatsApp (wa.me)": {"url": "https://wa.me/{username}", "method": "Web Scraping (Requires Phone Number)", "not_found_text": ["invalid number", "this link is invalid"], "note": "Only works if username is a valid phone number. May be blocked."},
        "OnlyFans": {"url": "https://onlyfans.com/{username}", "method": "Web Scraping", "not_found_text": ["page not found", "oops! we can’t find this page", "404"]},
        
        # --- Video Platforms ---
        "YouTube (Channel)": {"url": "https://www.youtube.com/@{username}/about", "method": "Web Scraping", "not_found_text": ["este canal não existe", "this channel does not exist"]},
        "Twitch": {"url": "https://www.twitch.tv/{username}", "method": "Web Scraping", "not_found_text": ["não existe", "page not found"]},
        "Vimeo": {"url": "https://vimeo.com/{username}", "method": "Web Scraping", "not_found_text": ["página não encontrada", "page not found"]},
        "Dailymotion": {"url": "https://www.dailymotion.com/{username}", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "Bilibili": {"url": "https://space.bilibili.com/{username}", "method": "Web Scraping", "not_found_text": ["404"]},
        
        # --- Music/Audio Platforms ---
        "SoundCloud": {"url": "https://soundcloud.com/{username}", "method": "Web Scraping", "not_found_text": ["this soundcloud is not available", "page not found"]},
        "Spotify (User)": {"url": "https://open.spotify.com/user/{username}", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "Bandcamp": {"url": "https://{username}.bandcamp.com", "method": "Web Scraping", "not_found_text": ["no results found", "page not found"]},
        "Last.fm": {"url": "https://www.last.fm/user/{username}", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "Mixcloud": {"url": "https://www.mixcloud.com/{username}", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "ReverbNation": {"url": "https://www.reverbnation.com/{username}", "method": "Web Scraping", "not_found_text": ["page not found"]},
        
        # --- Development/Technology Platforms ---
        "GitHub": {"url": "https://api.github.com/users/{username}", "method": "Public API", "json_field": "name", "not_found_text": ['{"message": "not found"', "page not found"]},
        "GitLab": {"url": "https://gitlab.com/{username}", "method": "Web Scraping", "not_found_text": ["page not found", "não encontrado"]},
        "Bitbucket": {"url": "https://bitbucket.org/{username}", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "CodePen": {"url": "https://codepen.io/{username}", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "Repl.it": {"url": "https://replit.com/@{username}", "method": "Web Scraping", "not_found_text": ["404: not found"]},
        "HackerRank": {"url": "https://www.hackerrank.com/{username}", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "LeetCode": {"url": "https://leetcode.com/{username}", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "StackOverflow": {"url": "https://stackoverflow.com/users/{username}", "method": "Web Scraping", "not_found_text": ["user not found"]},
        "SourceForge": {"url": "https://sourceforge.net/u/{username}/", "method": "Web Scraping", "not_found_text": ["no user found"]},
        "Dev.to": {"url": "https://dev.to/{username}", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "Hashnode": {"url": "https://hashnode.com/@{username}", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "Codeforces": {"url": "https://codeforces.com/profile/{username}", "method": "Web Scraping", "not_found_text": ["not found"]},
        "AtCoder": {"url": "https://atcoder.jp/users/{username}", "method": "Web Scraping", "not_found_text": ["not found"]},
        "Keybase": {"url": "https://keybase.io/{username}", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "Codecademy": {"url": "https://www.codecademy.com/profiles/{username}", "method": "Web Scraping", "not_found_text": ["user not found"]},
        "FreeCodeCamp": {"url": "https://www.freecodecamp.org/{username}", "method": "Web Scraping", "not_found_text": ["page not found", "not found"], "note": "URL might require specific ID format."},
        "Hackster.io": {"url": "https://www.hackster.io/{username}", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "Visual Studio Marketplace (Extensions)": {"url": "https://marketplace.visualstudio.com/items?itemName={username}", "method": "Web Scraping (for extensions)", "not_found_text": ["page not found"], "note": "Primary for extensions, not users."},
        
        # --- Art and Design ---
        "Dribbble": {"url": "https://dribbble.com/{username}", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "Behance": {"url": "https://www.behance.net/{username}", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "ArtStation": {"url": "https://www.artstation.com/{username}", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "500px": {"url": "https://500px.com/{username}", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "Unsplash": {"url": "https://unsplash.com/@{username}", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "Pixabay": {"url": "https://pixabay.com/users/{username}", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "Giphy": {"url": "https://giphy.com/{username}", "method": "Web Scraping", "not_found_text": ["page not found"]},

        # --- Blogs and Content ---
        "Medium": {"url": "https://medium.com/@{username}", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "Blogger": {"url": "https://{username}.blogspot.com", "method": "Web Scraping", "not_found_text": ["não existe", "not exist"]},
        "WordPress.com": {"url": "https://{username}.wordpress.com", "method": "Web Scraping", "not_found_text": ["doesn't exist"]},
        "Substack": {"url": "https://{username}.substack.com", "method": "Web Scraping", "not_found_text": ["this page doesn't exist"]},
        "Quora": {"url": "https://www.quora.com/profile/{username}", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "LiveJournal": {"url": "https://{username}.livejournal.com", "method": "Web Scraping", "not_found_text": ["not found"]},
        "Goodreads": {"url": "https://www.goodreads.com/user/show/{username}", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "Wattpad": {"url": "https://www.wattpad.com/user/{username}", "method": "Web Scraping", "not_found_text": ["user not found"]},
        "Issuu": {"url": "https://issuu.com/{username}", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "Scribd": {"url": "https://www.scribd.com/user/{username}", "method": "Web Scraping", "not_found_text": ["page not found"]},

        # --- Forums and Communities ---
        "Fandom (Wikia)": {"url": "https://community.fandom.com/wiki/User:{username}", "method": "Web Scraping", "not_found_text": ["não existe", "page not found"]},
        "Indie Hackers": {"url": "https://www.indiehackers.com/{username}", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "Product Hunt": {"url": "https://www.producthunt.com/@{username}", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "StackExchange": {"url": "https://stackexchange.com/users/{username}", "method": "Web Scraping", "not_found_text": ["user not found"]},
        "Brave Community": {"url": "https://community.brave.com/u/{username}/", "method": "Web Scraping", "not_found_text": ["page doesn’t exist or is private.", "not found"]},
        "Lastpass Community": {"url": "https://community.lastpass.com/t5/user/viewprofilepage/user-id/{username}", "method": "Web Scraping", "not_found_text": ["user not found"]},
        "Productivity Hunters": {"url": "https://productivity.stackexchange.com/users/{username}", "method": "Web Scraping", "not_found_text": ["user not found"]},
        
        # --- Gaming Platforms ---
        "Steam (Custom Profile)": {"url": "https://steamcommunity.com/id/{username}", "method": "Web Scraping", "not_found_text": ["no profile could be retrieved", "page not found"]},
        "Steam (Numeric ID)": {"url": "https://steamcommunity.com/profiles/{username}", "method": "Web Scraping", "not_found_text": ["no profile could be retrieved", "page not found"], "note": "Requires a numeric SteamID64."},
        "Itch.io": {"url": "https://{username}.itch.io", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "Chess.com": {"url": "https://www.chess.com/member/{username}", "method": "Web Scraping", "not_found_text": ["player not found"]},
        "Lichess": {"url": "https://lichess.org/@/{username}", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "Xbox Live (Gamertag Search)": {"url": "N/A", "method": "API not public", "note": "Requires official API or complex simulation for Gamertag."},
        "PlayStation Network (ID Search)": {"url": "N/A", "method": "API not public", "note": "Requires official API or complex simulation for PSN ID."},
        "Nintendo Network (ID Search)": {"url": "N/A", "method": "API not public", "note": "Requires official API or complex simulation for Nintendo ID."},
        "Epic Games": {"url": "https://www.epicgames.com/account/users/{username}", "method": "Web Scraping", "not_found_text": ["page not found"]}, # Unlikely to work via simple URL
        "Kick.com": {"url": "https://kick.com/{username}", "method": "Web Scraping", "not_found_text": ["page not found"]},
        
        # --- Books ---
        "Skoob (BR)": {"url": "https://www.skoob.com.br/usuario/{username}", "method": "Web Scraping", "not_found_text": ["usuário não encontrado"]},

        # --- Travel/Location ---
        "Foursquare": {"url": "https://foursquare.com/{username}", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "TripAdvisor": {"url": "https://www.tripadvisor.com/Profile/{username}", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "Airbnb (Not direct URL)": {"url": "N/A", "method": "API not public", "note": "User profiles are not publicly accessible via direct URL."},
        "Zillow": {"url": "https://www.zillow.com/profile/{username}", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "Yelp": {"url": "https://www.yelp.com/user_details?userid={username}", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "Houzz": {"url": "https://www.houzz.com/user/{username}", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "Geocaching": {"url": "https://www.geocaching.com/profile/?guid={username}", "method": "Web Scraping (Requires ID, not username)", "note": "This URL expects a GUID, not a simple username."},

        # --- Crowdfunding/Support ---
        "Kickstarter": {"url": "https://www.kickstarter.com/profile/{username}", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "Patreon": {"url": "https://www.patreon.com/{username}", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "Ko-fi": {"url": "https://ko-fi.com/{username}", "method": "Web Scraping", "not_found_text": ["page not found"]},

        # --- Education/Learning ---
        "Duolingo": {"url": "https://www.duolingo.com/profile/{username}", "method": "Web Scraping", "not_found_text": ["page not found"]},
        
        # --- Business/Professional ---
        "Crunchbase": {"url": "https://www.crunchbase.com/person/{username}", "method": "Web Scraping", "not_found_text": ["page not found", "cannot find person"]},
        "AngelList": {"url": "https://angel.co/{username}", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "Xing": {"url": "https://www.xing.com/profile/{username}", "method": "Web Scraping", "not_found_text": ["page not found"]},
        
        # --- Various Other Platforms ---
        "About.me": {"url": "https://about.me/{username}", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "Linktree": {"url": "https://linktr.ee/{username}", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "CalmlyWriter": {"url": "https://calmlywriter.com/{username}", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "GitBook": {"url": "https://app.gitbook.com/@{username}", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "OpenSea": {"url": "https://opensea.io/{username}", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "Etsy": {"url": "https://www.etsy.com/shop/{username}", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "eBay": {"url": "https://www.ebay.com/usr/{username}", "method": "Web Scraping", "not_found_text": ["member not found", "page not found"]},
        "Google Sites": {"url": "https://sites.google.com/view/{username}", "method": "Web Scraping", "not_found_text": ["not found"]},
        "Canva": {"url": "https://www.canva.com/p/{username}", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "Gravatar": {"url": "https://gravatar.com/{hashlib.md5(username.lower().encode('utf-8')).hexdigest()}", "method": "Status Check (via email hash - if username is email)", "not_found_text": ["page not found"], "note": "Only works if username is an email address."},
        "MyFitnessPal": {"url": "https://www.myfitnesspal.com/profile/{username}", "method": "Web Scraping", "not_found_text": ["profile not found"]},
        "Runkeeper": {"url": "https://runkeeper.com/user/{username}", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "Strava": {"url": "https://www.strava.com/athletes/{username}", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "Untappd": {"url": "https://untappd.com/user/{username}", "method": "Web Scraping", "not_found_text": ["user not found"]},
        "Vivino": {"url": "https://www.vivino.com/users/{username}", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "Zhihu": {"url": "https://www.zhihu.com/people/{username}", "method": "Web Scraping", "not_found_text": ["page not found", "404"]},
        "ResearchGate": {"url": "https://www.researchgate.net/profile/{username}", "method": "Web Scraping", "not_found_text": ["profile not found"]},
        "academia.edu": {"url": "https://{username}.academia.edu/", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "Smule": {"url": "https://www.smule.com/{username}", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "Taringa!": {"url": "https://www.taringa.net/{username}", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "TradingView": {"url": "https://www.tradingview.com/u/{username}/", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "Truecaller": {"url": "https://www.truecaller.com/users/{username}", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "Duolingo": {"url": "https://www.duolingo.com/profile/{username}", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "Poshmark": {"url": "https://poshmark.com/closet/{username}", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "Depop": {"url": "https://www.depop.com/{username}/", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "Discogs": {"url": "https://www.discogs.com/user/{username}", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "Etsy (Shop)": {"url": "https://www.etsy.com/shop/{username}", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "FanFiction.net": {"url": "https://www.fanfiction.net/u/{username}/", "method": "Web Scraping", "not_found_text": ["story not found"]}, # User profile URLs are by ID, not username usually
        "Fandom (General User)": {"url": "https://www.fandom.com/f/{username}", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "GameJolt": {"url": "https://gamejolt.com/@{username}", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "Genius": {"url": "https://genius.com/artists/{username}", "method": "Web Scraping", "not_found_text": ["page not found"], "note": "Primarily for artists/bands, not all users."},
        "Goodreads (Author)": {"url": "https://www.goodreads.com/author/show/{username}", "method": "Web Scraping", "not_found_text": ["page not found"], "note": "For authors, not regular users."},
        "IFTTT": {"url": "https://ifttt.com/p/{username}", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "Indiegogo": {"url": "https://www.indiegogo.com/individuals/{username}", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "Kaggle": {"url": "https://www.kaggle.com/{username}", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "Lastpass": {"url": "https://community.lastpass.com/t5/user/viewprofilepage/user-id/{username}", "method": "Web Scraping", "not_found_text": ["user not found"], "note": "Requires numeric user ID."},
        "Letterboxd": {"url": "https://letterboxd.com/{username}/", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "MyAnimeList": {"url": "https://myanimelist.net/profile/{username}", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "NameMC (Minecraft)": {"url": "https://namemc.com/profile/{username}", "method": "Web Scraping", "not_found_text": ["profile not found"]},
        "Niantic Wayfarer": {"url": "https://community.wayfarer.nianticlabs.com/profile/{username}", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "OpenStreetMap": {"url": "https://www.openstreetmap.org/user/{username}", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "Overleaf": {"url": "https://www.overleaf.com/public/{username}", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "Patreon (Creator)": {"url": "https://www.patreon.com/{username}", "method": "Web Scraping", "not_found_text": ["page not found"], "note": "For creators, not patrons."},
        "Picuki (Instagram Viewer)": {"url": "https://www.picuki.com/profile/{username}", "method": "Web Scraping", "not_found_text": ["user not found"], "note": "Third-party viewer, unstable."},
        "Plex.tv": {"url": "https://app.plex.tv/desktop/#!/settings/account/{username}", "method": "Web Scraping", "not_found_text": ["page not found"], "note": "Requires authenticated session."},
        "Redbubble": {"url": "https://www.redbubble.com/people/{username}/shop", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "Resumake.ai": {"url": "https://resumake.ai/{username}", "method": "Web Scraping", "not_found_text": ["page not found"], "note": "For generated resumes, not general profiles."},
        "Roblox": {"url": "https://www.roblox.com/users/{username}/profile", "method": "Web Scraping", "not_found_text": ["page not found"], "note": "Requires numeric user ID."},
        "Snapchat (Public Profiles)": {"url": "https://www.snapchat.com/add/{username}", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "Steamgifts": {"url": "https://www.steamgifts.com/user/{username}", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "Strava (Activity)": {"url": "https://www.strava.com/athletes/{username}/activity", "method": "Web Scraping", "not_found_text": ["page not found"], "note": "For activities, not main profile."},
        "Toptal": {"url": "https://www.toptal.com/remote/{username}", "method": "Web Scraping", "not_found_text": ["page not found"], "note": "For Toptal freelancers."},
        "Transfermarkt": {"url": "https://www.transfermarkt.com/profil/spieler/{username}", "method": "Web Scraping", "not_found_text": ["page not found"], "note": "For football players, not general users."},
        "Truecaller (User Search)": {"url": "https://www.truecaller.com/users/{username}", "method": "Web Scraping", "not_found_text": ["page not found"], "note": "Primarily phone number search."},
        "Untappd (User)": {"url": "https://untappd.com/user/{username}", "method": "Web Scraping", "not_found_text": ["user not found"]},
        "WeHeartIt": {"url": "https://weheartit.com/{username}", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "Wikipedia (Talk Page)": {"url": "https://pt.wikipedia.org/wiki/Usuário Discussão:{username}", "method": "Web Scraping", "not_found_text": ["não existe", "page not found"]},
        "Xing (Profile)": {"url": "https://www.xing.com/profile/{username}", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "Zomato": {"url": "https://www.zomato.com/users/{username}", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "App Store (Developer)": {"url": "https://apps.apple.com/us/developer/{username}/id{username}", "method": "Web Scraping (Requires ID)", "not_found_text": ["not found"], "note": "Requires Developer ID, not username."},
        "Google Play Store (Developer)": {"url": "https://play.google.com/store/apps/dev?id={username}", "method": "Web Scraping (Requires ID)", "not_found_text": ["not found"], "note": "Requires Developer ID, not username."},
        "Microsoft Store (Developer)": {"url": "https://www.microsoft.com/en-us/store/collections/developers/{username}", "method": "Web Scraping (Requires ID)", "not_found_text": ["not found"], "note": "Requires Developer ID, not username."},
        "Crunchyroll": {"url": "https://www.crunchyroll.com/user/{username}", "method": "Web Scraping", "not_found_text": ["user not found"]},
        "MyAnimeList": {"url": "https://myanimelist.net/profile/{username}", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "Smogon": {"url": "https://www.smogon.com/forums/members/{username}.{username_id}/", "method": "Web Scraping", "not_found_text": ["page not found"], "note": "Requires both username and a numeric ID."},
        "TV Time": {"url": "https://www.tvtime.com/user/{username}/profile", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "Goodreads (Book)": {"url": "https://www.goodreads.com/book/show/{username}", "method": "Web Scraping (if username is book ID)", "not_found_text": ["page not found"], "note": "For books, not users, unless username is a book ID."},
        "TheMovieDatabase (TMDB)": {"url": "https://www.themoviedb.org/person/{username}", "method": "Web Scraping (if username is person ID)", "not_found_text": ["page not found"], "note": "For people/movies, not general users, unless username is a person ID."},
        "Letterboxd (User)": {"url": "https://letterboxd.com/{username}/", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "Vsco": {"url": "https://vsco.co/{username}/gallery", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "Ello": {"url": "https://ello.co/{username}", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "Diaspora* (Example .com)": {"url": "https://diasp.org/u/{username}", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "Gab": {"url": "https://gab.com/{username}", "method": "Web Scraping", "not_found_text": ["page not found", "account not found"]},
        "Parler": {"url": "https://parler.com/profile/{username}", "method": "Web Scraping", "not_found_text": ["page not found"]}, # Site has been unstable
        "Minds": {"url": "https://www.minds.com/{username}/", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "MeWe": {"url": "https://mewe.com/{username}/", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "Ok.ru": {"url": "https://ok.ru/profile/{username}", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "LiveLeak (Archives)": {"url": "N/A", "method": "Archives", "note": "LiveLeak is offline. Search archives if needed."},
        "Bitchute": {"url": "https://www.bitchute.com/channel/{username}/", "method": "Web Scraping", "not_found_text": ["channel not found"]},
        "DLive": {"url": "https://dlive.tv/{username}", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "BrandMe": {"url": "https://brand.me/{username}", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "Canva (Public Profile)": {"url": "https://www.canva.com/p/{username}", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "Classmates.com": {"url": "https://www.classmates.com/{username}", "method": "Web Scraping", "not_found_text": ["page not found"]}, # Requires login for most content
        "Codeigniter": {"url": "https://forum.codeigniter.com/member.php?action=profile&uid={username}", "method": "Web Scraping", "not_found_text": ["invalid user id"], "note": "Requires numeric user ID."},
        "Coroflot": {"url": "https://www.coroflot.com/{username}", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "Craigslist (User)": {"url": "https://{location}.craigslist.org/search/sss?query={username}&sort=date", "method": "Web Scraping", "not_found_text": ["no results"], "note": "Requires location (e.g., sfbay). Not a direct user profile."},
        "Dating.com": {"url": "https://www.dating.com/profile/{username}", "method": "Web Scraping", "not_found_text": ["page not found"], "note": "Requires direct ID, likely blocked."},
        "DeviantArt (Groups)": {"url": "https://www.deviantart.com/users/profile/groups/{username}", "method": "Web Scraping", "not_found_text": ["page not found"], "note": "For groups, not individual user profiles directly."},
        "Disqus": {"url": "https://disqus.com/by/{username}/", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "Doomworld": {"url": "https://www.doomworld.com/profile/{username}/", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "Dribbble (Team)": {"url": "https://dribbble.com/teams/{username}", "method": "Web Scraping", "not_found_text": ["page not found"], "note": "For teams, not individual users."},
        "Etsy (Team)": {"url": "https://www.etsy.com/teams/{username}", "method": "Web Scraping", "not_found_text": ["page not found"], "note": "For teams, not individual users."},
        "FanGraphs": {"url": "https://www.fangraphs.com/players/{username}", "method": "Web Scraping", "not_found_text": ["page not found"], "note": "For baseball players, not general users."},
        "Fiverr (Seller)": {"url": "https://www.fiverr.com/{username}", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "Foodspotting": {"url": "https://www.foodspotting.com/places/{username}", "method": "Web Scraping", "not_found_text": ["page not found"], "note": "For locations, not users."},
        "GameFAQs": {"url": "https://gamefaqs.gamespot.com/community/user/{username}", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "Goodreads (Review)": {"url": "https://www.goodreads.com/review/show/{username}", "method": "Web Scraping", "not_found_text": ["page not found"], "note": "For reviews, not users."},
        "Habbo (User)": {"url": "https://www.habbo.com/profile/{username}", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "Instructables": {"url": "https://www.instructables.com/member/{username}/", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "Kaggle (User)": {"url": "https://www.kaggle.com/{username}", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "Ko-fi (User)": {"url": "https://ko-fi.com/{username}", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "Last.fm (Group)": {"url": "https://www.last.fm/group/{username}", "method": "Web Scraping", "not_found_text": ["page not found"], "note": "For groups, not users."},
        "Letterboxd (List)": {"url": "https://letterboxd.com/list/{username}", "method": "Web Scraping", "not_found_text": ["page not found"], "note": "For lists, not users."},
        "LibriVox": {"url": "https://librivox.org/author/{username}", "method": "Web Scraping", "not_found_text": ["page not found"], "note": "For authors, not general users."},
        "MyAnimeList (User)": {"url": "https://myanimelist.net/profile/{username}", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "NationStates": {"url": "https://www.nationstates.net/nation={username}", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "OpenHub": {"url": "https://www.openhub.net/accounts/{username}", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "Patreon (Campaign)": {"url": "https://www.patreon.com/user?u={username}", "method": "Web Scraping", "not_found_text": ["page not found"], "note": "For campaign ID, not username."},
        "Periscope (Archived)": {"url": "https://www.pscp.tv/w/{username}", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "Pexels (User)": {"url": "https://www.pexels.com/@{username}", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "Photobucket": {"url": "https://photobucket.com/user/{username}/profile", "method": "Web Scraping", "not_found_text": ["page not found"], "note": "Site has changed significantly."},
        "Pixabay (User)": {"url": "https://pixabay.com/users/{username}/", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "Pixiv": {"url": "https://www.pixiv.net/en/users/{username}", "method": "Web Scraping", "not_found_text": ["user not found"], "note": "Requires numeric user ID."},
        "Player.me": {"url": "https://player.me/{username}", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "ProtonMail (Blog)": {"url": "https://proton.me/blog/author/{username}", "method": "Web Scraping", "not_found_text": ["page not found"], "note": "For blog authors."},
        "Reverb (User)": {"url": "https://reverb.com/shop/{username}", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "Roblox (Profile - Username Search)": {"url": "https://www.roblox.com/users/profile?username={username}", "method": "Web Scraping", "not_found_text": ["page not found"], "note": "Unreliable direct username search."},
        "RuneScape": {"url": "https://apps.runescape.com/runemetrics/profile/profile?user={username}", "method": "Web Scraping", "not_found_text": ["no profile found"]},
        "Sketchfab": {"url": "https://sketchfab.com/{username}", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "Spreaker": {"url": "https://www.spreaker.com/user/{username}", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "Talenthouse": {"url": "https://www.talenthouse.com/{username}", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "TheFork": {"url": "https://www.thefork.com/restaurant/{username}", "method": "Web Scraping", "not_found_text": ["page not found"], "note": "For restaurants, not users."},
        "Vero (Public Profile)": {"url": "https://vero.co/app/{username}", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "Wikimapia": {"url": "http://wikimapia.org/user/{username}/", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "YouNow": {"url": "https://www.younow.com/{username}/", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "Academia.edu": {"url": "https://{username}.academia.edu/", "method": "Web Scraping", "not_found_text": ["page not found"]}, # Already in the list, but adding a variation for emphasis
        "Bandcamp (Artist)": {"url": "https://{username}.bandcamp.com/", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "Bluesky (Profile)": {"url": "https://bsky.app/profile/{username}.bsky.social", "method": "Web Scraping", "not_found_text": ["page not found", "not found"], "note": "Assumes standard bsky.social domain."},
        "Carrd.co": {"url": "https://{username}.carrd.co/", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "Dribbble (Player)": {"url": "https://dribbble.com/players/{username}", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "Etsy (Pattern)": {"url": "https://www.etsy.com/pattern/{username}", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "FanDuel": {"url": "https://www.fanduel.com/users/{username}", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "Flipboard": {"url": "https://flipboard.com/@{username}", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "Goodreads (Group)": {"url": "https://www.goodreads.com/group/show/{username}", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "Hey.com (World)": {"url": "https://world.hey.com/{username}", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "Kaggle (Dataset)": {"url": "https://www.kaggle.com/datasets/{username}", "method": "Web Scraping", "not_found_text": ["page not found"], "note": "For datasets, not users."},
        "Libera.Chat (IRC Nick)": {"url": "N/A", "method": "IRC/Community (No direct URL)", "note": "IRC network, no public user profiles via web."},
        "ManyVids": {"url": "https://www.manyvids.com/Profile/{username}/", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "Medium (Tag)": {"url": "https://medium.com/tag/{username}", "method": "Web Scraping", "not_found_text": ["page not found"], "note": "For tags, not users."},
        "NPM (Package Author)": {"url": "https://www.npmjs.com/~{username}", "method": "Web Scraping", "not_found_text": ["not found"]},
        "OpenCollective": {"url": "https://opencollective.com/{username}", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "PeerTube (Example .fr)": {"url": "https://framatube.org/accounts/username", "method": "Web Scraping", "not_found_text": ["page not found"], "note": "Decentralized, instance dependent."},
        "Pexels (Photo)": {"url": "https://www.pexels.com/photo/{username}/", "method": "Web Scraping", "not_found_text": ["page not found"], "note": "For photos, not users."},
        "Picsart": {"url": "https://picsart.com/u/{username}", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "Pikabu": {"url": "https://pikabu.ru/@{username}", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "Post.news": {"url": "https://www.post.news/{username}", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "Quizlet": {"url": "https://quizlet.com/{username}", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "Revolut (Community)": {"url": "https://community.revolut.com/u/{username}/summary", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "Sketchfab (Download)": {"url": "https://sketchfab.com/models/{username}/download", "method": "Web Scraping", "not_found_text": ["page not found"], "note": "For models, not users."},
        "Slant": {"url": "https://www.slant.co/users/{username}", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "Smash.gg (User)": {"url": "https://smash.gg/user/{username}", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "Splice": {"url": "https://splice.com/{username}", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "StackBlitz": {"url": "https://stackblitz.com/@{username}", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "Taringa! (Community)": {"url": "https://www.taringa.net/comunidades/{username}/", "method": "Web Scraping", "not_found_text": ["page not found"], "note": "For communities, not users."},
        "TensorFlow (Community)": {"url": "https://community.tensorflow.org/u/{username}/summary", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "TheSpruce": {"url": "https://www.thespruce.com/search?q={username}", "method": "Web Scraping", "not_found_text": ["no results found"], "note": "Search, not profile."},
        "Trello (Public Profile)": {"url": "https://trello.com/{username}", "method": "Web Scraping", "not_found_text": ["page not found"], "note": "Only if public profile is enabled."},
        "Udemy": {"url": "https://www.udemy.com/user/{username}/", "method": "Web Scraping", "not_found_text": ["page not found"], "note": "For instructors, not all users."},
        "Unsplash (Photo)": {"url": "https://unsplash.com/photos/{username}", "method": "Web Scraping", "not_found_text": ["page not found"], "note": "For photos, not users."},
        "Upwork": {"url": "https://www.upwork.com/freelancers/~{username}", "method": "Web Scraping", "not_found_text": ["page not found"], "note": "For freelancers, requires ~ prefix."},
        "Vero (Creator)": {"url": "https://vero.co/app/creator/{username}", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "Webflow": {"url": "https://webflow.com/{username}", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "Write.as": {"url": "https://write.as/{username}", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "Youpic": {"url": "https://youpic.com/photographer/{username}/", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "Zuiker.com": {"url": "https://zuiker.com/profile/{username}", "method": "Web Scraping", "not_found_text": ["page not found"]},
        # More specific/niche platforms
        "Keybase (Git)": {"url": "https://keybase.io/{username}/git", "method": "Web Scraping", "not_found_text": ["page not found"], "note": "For Keybase Git repos."},
        "MySpace (Archived)": {"url": "https://myspace.com/{username}", "method": "Web Scraping", "not_found_text": ["page not found"], "note": "Mostly archived, limited public profiles."},
        "SlideShare (User)": {"url": "https://www.slideshare.net/{username}", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "Speaker Deck": {"url": "https://speakerdeck.com/{username}", "method": "Web Scraping", "not_found_text": ["page not found"]},
        "Telegram (Group Chat - Username)": {"url": "https://t.me/joinchat/{username}", "method": "Web Scraping", "not_found_text": ["page not found"], "note": "For group chat links, not user profiles."},
        "Fiverr (Buyer)": {"url": "https://www.fiverr.com/buyers/{username}", "method": "Web Scraping", "not_found_text": ["page not found"], "note": "Unlikely to work without specific ID."},
        "Imgur (Album)": {"url": "https://imgur.com/a/{username}", "method": "Web Scraping", "not_found_text": ["page not found"], "note": "For albums, not users."},
        "LiveJournal (Community)": {"url": "https://{username}.livejournal.com/community/", "method": "Web Scraping", "not_found_text": ["page not found"], "note": "For communities, not users."},
        "Patreon (Post)": {"url": "https://www.patreon.com/posts/{username}", "method": "Web Scraping", "not_found_text": ["page not found"], "note": "For posts, not users."},
        "Redbubble (Collection)": {"url": "https://www.redbubble.com/people/{username}/collections", "method": "Web Scraping", "not_found_text": ["page not found"], "note": "For collections, not users."},
        "Steam (Groups)": {"url": "https://steamcommunity.com/groups/{username}", "method": "Web Scraping", "not_found_text": ["page not found"], "note": "For groups, not users."},
        "Twitch (VOD)": {"url": "https://www.twitch.tv/{username}/videos", "method": "Web Scraping", "not_found_text": ["page not found"], "note": "For VODs, not general user profile check."},
        "YouTube (User Legacy)": {"url": "https://www.youtube.com/user/{username}", "method": "Web Scraping", "not_found_text": ["this channel does not exist"], "note": "Legacy user URLs, most migrated to @username."},

    }

    session = requests.Session()
    # Ensure proxies are used for the session
    if Config.PROXIES:
        session.proxies = Config.PROXIES

    future_list = []
    for site_name, site_config in sites.items():
        if site_config["url"] == "N/A":
            results[site_name] = {'exists': False, 'url': site_config['url'], 'method': site_config['method'], 'note': site_config.get('note', 'Not verifiable via direct URL.')}
        else:
            future_list.append(executor.submit(_check_single_profile, session, username, site_name, site_config))
    
    # Use tqdm for a progress bar
    for future in tqdm(as_completed(future_list), total=len(future_list), desc=f"{Fore.GREEN}Checking profiles for {username}{Style.RESET_ALL}", unit="site"):
        site_name_from_future = future.result().get('site_name_debug') # Debug field to get site name
        try:
            result = future.result()
            if 'site_name_debug' in result:
                del result['site_name_debug']
            results[site_name_from_future if site_name_from_future else "Unknown"] = result
        except Exception as e:
            logging.error(f"{Fore.RED}Unexpected error collecting future result for {site_name_from_future}: {e}{Style.RESET_ALL}")
            if site_name_from_future:
                results[site_name_from_future] = {'error': str(e), 'exists': False, 'url': sites.get(site_name_from_future, {}).get('url', 'N/A')}
            else:
                 results["Unknown Error"] = {'error': str(e), 'exists': False, 'url': 'N/A'}
    
    return results

def _check_single_profile(session: requests.Session, username: str, site_name: str, config: Dict) -> Dict[str, Any]:
    """Helper function to safely verify a single profile."""
    time.sleep(0.1) # Small pause to avoid rate limiting (adjust as needed)
    
    # Add site name for debugging in case of future.result() error
    result_template = {
        'exists': False,
        'url': config["url"].format(username=username),
        'method': config["method"],
        'profile_name_found': username, # Default value, will be updated if found
        'status_code': 'N/A',
        'error': None,
        'site_name_debug': site_name # For debugging in as_completed
    }

    url = result_template['url']
    
    # Prepare custom headers for each request
    headers = {
        'User-Agent': get_random_user_agent(),
        'Accept-Language': 'en-US,en;q=0.9,pt-BR;q=0.8,pt;q=0.7',
        'Referer': url # Referer can be self-referential or a generic popular site
    }
    # Add specific referers if needed for certain sites
    if site_name == "Instagram":
        headers['Referer'] = "https://www.instagram.com/"
    elif site_name == "Twitter/X":
        headers['Referer'] = "https://twitter.com/"

    logging.debug(f"Checking {site_name}: {url}")
    try:
        response = session.get( # Use the session object
            url,
            headers=headers,
            timeout=Config.REQUEST_TIMEOUT,
            allow_redirects=True # Follow redirects is important for profiles
        )
        
        result_template['status_code'] = response.status_code
        
        exists = False

        # Check if status code is 200 OK and does not contain "not found" text
        if response.status_code == 200:
            if config.get("not_found_text"):
                content_lower = response.text.lower()
                is_not_found_by_text = False
                for text in config["not_found_text"]:
                    if text.lower() in content_lower:
                        is_not_found_by_text = True
                        break
                if not is_not_found_by_text:
                    exists = True
            else: # If no not_found_text, 200 OK implies existence
                exists = True
        elif response.status_code == 404: # 404 is a good indicator of non-existence
            exists = False
        # For other codes (e.g., 403 Forbidden, 500 Internal Server Error),
        # assume non-existence for search purpose but log the error.
        else:
            logging.warning(f"{Fore.YELLOW}Unexpected response for {site_name} ({url}): Status {response.status_code}{Style.RESET_ALL}")
            result_template['error'] = f"HTTP Unexpected Status: {response.status_code}"
            exists = False

        result_template['exists'] = exists

        # Try to extract profile name for JSON APIs or simple web scraping (if exists is True)
        if exists and response.status_code == 200:
            if config.get("json_field"):
                try:
                    json_data = response.json()
                    fields = config["json_field"].split('.')
                    value = json_data
                    for field in fields:
                        if isinstance(value, dict):
                            value = value.get(field)
                        else: # If path is not a dict, field doesn't exist
                            value = None
                            break
                    if value and not isinstance(value, dict) and not isinstance(value, list):
                        result_template['profile_name_found'] = value
                except json.JSONDecodeError:
                    logging.debug(f"Could not decode JSON for {site_name}. Skipping name extraction via JSON.")
                except Exception as e:
                    logging.debug(f"Error extracting JSON for {site_name}: {e}")
            
            # Additional for sites where username is directly visible and means existence
            elif site_name in ["Twitter/X", "Telegram (Public Channel/User)"] and exists:
                result_template['profile_name_found'] = username # Assume the search username

        return result_template
    except Timeout:
        logging.warning(f"{Fore.YELLOW}Timeout checking {site_name} ({url}).{Style.RESET_ALL}")
        result_template['error'] = 'Timeout'
        result_template['exists'] = False
        return result_template
    except (RequestException, ConnectionError) as e:
        logging.warning(f"{Fore.YELLOW}Request error checking {site_name} ({url}): {str(e)}{Style.RESET_ALL}")
        result_template['error'] = str(e)
        result_template['exists'] = False
        return result_template
    except Exception as e:
        logging.error(f"{Fore.RED}Unexpected error checking {site_name} ({url}): {str(e)}{Style.RESET_ALL}")
        result_template['error'] = str(e)
        result_template['exists'] = False
        return result_template

def display_eriknet_results(data: Dict[str, Any], title: str) -> None:
    """Displays search results in a formatted way."""
    clear_screen() # Clear screen before showing results
    print(BANNER) # Redisplay banner
    print(f"\n{Fore.CYAN}═"*80 + Style.RESET_ALL)
    print(f"{Fore.CYAN} {title.upper()} RESULTS ".center(80) + Style.RESET_ALL)
    print(f"{Fore.CYAN}═"*80 + Style.RESET_ALL)
    
    found_count = 0
    total_verified = 0
    
    # Ensure consistent order (alphabetical by platform)
    for platform in sorted(data.keys()):
        info = data[platform]
        
        if 'error' in info and info['error'] is not None:
            print(f"\n{Fore.RED}▓ {platform.upper()}{Style.RESET_ALL}")
            print(f"  🔴 ERROR: {info['error']}")
            print(f"  🌐 URL: {info.get('url', 'N/A')}")
            if info.get('status_code') != 'N/A':
                 print(f"  HTTP STATUS: {info['status_code']}")
        elif 'note' in info: # For cases like Xbox/PSN that are not direct URLs
            total_verified += 1
            print(f"\n{Fore.YELLOW}▓ {platform.upper()}{Style.RESET_ALL}")
            print(f"  🟡 NOTE: {info['note']}")
            print(f"  🌐 URL: {info.get('url', 'N/A')}")
            print(f"  ⚙️ METHOD: {info.get('method', 'N/A')}")
        elif platform == "Holehe Status": # Special handling for Holehe
            total_verified += 1
            status_color = Fore.GREEN if info.get('exists') else Fore.RED
            status_text = "SUCCESS" if info.get('exists') else "FAILURE"
            print(f"\n{status_color}▓ HOLEHE (EMAIL VERIFICATION){Style.RESET_ALL}")
            print(f"  {status_color}STATUS: {status_text}{Style.RESET_ALL}")
            if info.get('data') and info['data'].get('raw_output'):
                print(f"  RAW OUTPUT (partial): {info['data']['raw_output'][:200]}...") # Show beginning of output
            elif info.get('error'):
                print(f"  ERROR: {info['error']}")
        else: # Regular profile checks
            total_verified += 1
            status_color = Fore.RED
            status_text = "NOT FOUND"
            
            if info.get('exists'):
                found_count += 1
                status_color = Fore.GREEN
                status_text = "FOUND"
            
            print(f"\n{status_color}▓ {platform.upper()}{Style.RESET_ALL}")
            print(f"  {status_color}STATUS: {status_text}{Style.RESET_ALL}")
            print(f"  🌐 URL: {info.get('url', 'N/A')}")
            
            # Display profile_name_found if it differs from the guessed username (or is explicitly set)
            if info.get('profile_name_found') and str(info['profile_name_found']).lower() != info.get('url', '').split('/')[-2].replace('@', '').lower():
                print(f"  📛 PROFILE NAME: {info['profile_name_found']}")
            elif info.get('profile_name_found'):
                print(f"  📛 USERNAME: {info['profile_name_found']}")
            
            print(f"  ⚙️ METHOD: {info.get('method', 'N/A')}")
            if info.get('status_code') != 'N/A':
                 print(f"  HTTP STATUS: {info['status_code']}")

            # Specific details for Gmail heuristic
            if platform == "Gmail (Verificação Heurística)" and info.get('details'):
                print(f"  DETAILS (Heuristic):")
                print(f"    - GX Cookie Detected: {info['details'].get('gx_cookie_detected')}")
                print(f"    - Set-Cookie Header Detected: {info['details'].get('set_cookie_header_detected')}")
                print(f"    - Username Unavailable in Signup: {info['details'].get('username_unavailable_in_signup')}")

    print(f"\n{Fore.CYAN}═"*80 + Style.RESET_ALL)
    print(f"{Fore.CYAN} SUMMARY: {found_count} out of {total_verified} platforms with found profiles ".center(80) + Style.RESET_ALL)
    print(f"{Fore.CYAN}═"*80 + Style.RESET_ALL)

def export_to_json(data: Dict[str, Any], file_prefix: str) -> None:
    """Exports search results to a JSON file."""
    timestamp = int(time.time())
    file_name = f"eriknet_results_{file_prefix}_{timestamp}.json"
    file_path = os.path.join(Config.RESULTS_FOLDER, file_name)
    
    try:
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=4, ensure_ascii=False)
        logging.info(f"{Fore.GREEN}✅ Results exported to: {file_path}{Style.RESET_ALL}")
    except Exception as e:
        logging.error(f"{Fore.RED}❌ Error exporting results to JSON: {str(e)}{Style.RESET_ALL}")

def main_menu() -> int:
    """Displays the main menu and gets user's choice."""
    clear_screen()
    print(BANNER)
    print(f"\n[{datetime.now().strftime('%d/%m/%Y %H:%M:%S')}]")
    print("\n1. Search by username (100+ platforms)")
    print("2. Search by email (with Holehe and Gmail verification)")
    print("3. Export last results to JSON")
    print("4. Exit")
    
    try:
        choice = input(f"\n{Fore.CYAN}Choose an option (1-4): {Style.RESET_ALL}").strip()
        return int(choice)
    except ValueError:
        return 0 # Invalid option

def run_search():
    """Main execution loop for ErikNet."""
    last_results: Optional[Dict[str, Any]] = None
    last_file_prefix: Optional[str] = None
    
    while True:
        option = main_menu()
        
        if option == 1:
            username = input(f"\n{Fore.YELLOW}Enter username: {Style.RESET_ALL}").strip()
            # Basic validation for username
            if not username or len(username) < 2 or re.search(r'\s', username):
                logging.warning(f"{Fore.YELLOW}Invalid username! Cannot be empty, must be at least 2 characters, and no spaces.{Style.RESET_ALL}")
                time.sleep(2)
                continue
            
            logging.info(f"\n{Fore.BLUE}🔍 Searching across 100+ platforms for: {username}...{Style.RESET_ALL}")
            last_results = search_profiles(username)
            last_file_prefix = f"username_{username}"
            display_eriknet_results(last_results, f"Username Search: {username}")
            
        elif option == 2:
            email = input(f"\n{Fore.YELLOW}Enter email: {Style.RESET_ALL}").strip()
            # Robust email validation
            if not email or not re.match(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$", email):
                logging.warning(f"{Fore.YELLOW}Invalid or empty email format!{Style.RESET_ALL}")
                time.sleep(2)
                continue

            username_from_email = email.split('@')[0]
            
            logging.info(f"\n{Fore.BLUE}🔍 Starting email search for: {email}...{Style.RESET_ALL}")

            combined_results = {}

            # Execute Holehe
            holehe_result_dict = execute_holehe(email)
            combined_results["Holehe Status"] = holehe_result_dict
            
            # Additional Gmail heuristic verification
            gmail_check_result = verify_gmail_heuristic(email)
            combined_results["Gmail (Heuristic Verification)"] = gmail_check_result
            
            # Search for social profiles using username derived from email
            logging.info(f"\n{Fore.BLUE}🔍 Searching social profiles for username derived from email: {username_from_email}...{Style.RESET_ALL}")
            social_profiles_results = search_profiles(username_from_email)
            combined_results.update(social_profiles_results) # Add profile search results
            
            last_results = combined_results
            last_file_prefix = f"email_{email.replace('@', '_').replace('.', '_')}"
            display_eriknet_results(last_results, f"Email Search: {email}")
            
        elif option == 3: # Export results
            if last_results and last_file_prefix:
                export_to_json(last_results, last_file_prefix)
            else:
                logging.warning(f"{Fore.YELLOW}❌ No results available to export. Perform a search first.{Style.RESET_ALL}")
            
        elif option == 4: # Exit
            logging.info(f"{Fore.GREEN}\nExiting ErikNet...{Style.RESET_ALL}")
            break
            
        else:
            logging.warning(f"{Fore.YELLOW}Invalid option! Please try again.{Style.RESET_ALL}")
            time.sleep(1)
            
        if option != 4: # Don't ask for Enter if exiting
            input(f"\n{Fore.CYAN}Press Enter to continue...{Style.RESET_ALL}")

if __name__ == "__main__":
    try:
        run_search()
    except KeyboardInterrupt:
        logging.info(f"{Fore.YELLOW}\n\nErikNet interrupted by user!{Style.RESET_ALL}")
    except Exception as e:
        logging.critical(f"{Fore.RED}\nCRITICAL UNEXPECTED ERROR: {str(e)}{Style.RESET_ALL}", exc_info=True)
    finally:
        logging.info(f"{Fore.GREEN}\nThank you for using ErikNet! Security always.\n{Style.RESET_ALL}")

