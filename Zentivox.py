# These lines bring in tools (libraries) that help the program do specific jobs, like fetching web data, making a window, or keeping a log.
import aiohttp  # Tool to grab information from websites quickly.
import json  # Tool to read and write data in a simple format called JSON.
import time  # Tool to handle timing, like waiting or checking how long something takes.
from datetime import datetime  # Tool to work with dates and times, like "February 22, 2025, 4:31 PM."
import feedparser  # Tool to read news feeds (RSS) from websites.
import webbrowser  # Tool to open web links in your browser, like clicking a URL.
from bs4 import BeautifulSoup  # Tool to clean up messy web text and make it readable.
import tkinter as tk  # Tool to create a window with buttons and text (the app’s face).
from tkinter import scrolledtext, ttk, filedialog  # Extra tools for the window: scrollable text, dropdowns, and file-saving popups.
import asyncio  # Tool to let the program do many things at once, like fetching news while showing the window.
import sys  # Tool to control how the program starts or stops.
import logging  # Tool to write a diary (log) of what the program does, for troubleshooting.
import threading  # Tool to run tasks in the background, like refreshing news without freezing the window.
from dateutil import parser as date_parser  # Tool to understand dates written in different ways, like "2025-02-22" or "Feb 22, 2025."

# --- Configuration ---
# This section sets up the basic settings for Zentivox, like where to get updates and how often to check.
CVE_SOURCES = {  # A list of websites with cybersecurity alerts (CVEs = Common Vulnerabilities and Exposures).
    "NIST NVD": "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=10&startIndex=0",  # Gets 10 recent alerts from a government database.
    "CISA Alerts": "https://www.cisa.gov/cybersecurity-advisories/all.xml",  # Gets alerts from a U.S. cybersecurity agency.
    "Exploit-DB": "https://www.exploit-db.com/rss.xml",  # Gets hacking-related alerts from a public database.
}
NEWS_SOURCES = {  # A list of websites with cybersecurity news articles.
    "Bleeping Computer": "https://www.bleepingcomputer.com/feed/",  # Tech news site with security updates.
    "The Hacker News": "https://thehackernews.com/rss.xml",  # Popular cybersecurity news site.
    "Security Affairs": "https://securityaffairs.co/feed/",  # Another security news blog.
    "Wired (Security)": "https://www.wired.com/feed/category/security/latest/rss",  # Security section of a tech magazine.
    "Krebs on Security": "https://krebsonsecurity.com/feed/",  # Blog by a famous security expert.
}
DATE_FORMAT_DISPLAY = "%Y-%m-%d %H:%M:%S"  # How dates will look in Zentivox, e.g., "2025-02-22 16:31:45."
NOTIFICATION_INTERVAL_SECONDS = 300  # How often Zentivox checks for new updates (300 seconds = 5 minutes).
STATE_FILE = "zentivox_state.json"  # A file to remember the last time Zentivox checked for updates.
NIST_TIMEOUT = 60  # How long to wait (in seconds) for the NIST NVD site to respond before giving up.
DEFAULT_TIMEOUT = 30  # How long to wait for other websites to respond before giving up.

# Setup logging
# This tells Zentivox to keep a diary (log) of everything it does, saved in a file called "zentivox.log."
logging.basicConfig(
    filename="zentivox.log",  # Where the diary is saved (renamed from cybersecurity_notifier.log).
    level=logging.DEBUG,  # Write down every little detail (DEBUG mode).
    format="%(asctime)s - %(levelname)s - %(message)s"  # How each diary entry looks, e.g., "2025-02-22 16:31:45 - DEBUG - Doing something."
)

# --- Async Data Fetching ---
# These functions are like helpers that go out to the internet and bring back cybersecurity alerts and news for Zentivox.

async def fetch_cve_data(cve_url, source_name, retry=False):
    """This helper grabs cybersecurity alerts from websites like NIST NVD, CISA, or Exploit-DB for Zentivox."""
    if source_name == "NIST NVD":  # Special instructions for the NIST NVD website.
        async with aiohttp.ClientSession() as session:  # Opens a connection to the internet.
            try:
                logging.debug(f"Fetching {source_name} from {cve_url} with timeout {NIST_TIMEOUT}s")  # Write in the diary: "Trying to get data from NIST NVD."
                async with session.get(cve_url, headers={'User-Agent': 'Zentivox/1.0'}, timeout=aiohttp.ClientTimeout(total=NIST_TIMEOUT)) as response:
                    # Ask the website for data, saying "I’m Zentivox," and wait up to 60 seconds (changed from CybersecurityNotifier).
                    response.raise_for_status()  # Make sure the website says "OK" and not "Error."
                    data = await response.json()  # Get the data in a format we can read (JSON).
                    items = []  # A basket to hold the alerts we find.
                    for vuln in data.get("vulnerabilities", []):  # Look through each alert in the data.
                        cve = vuln.get("cve", {})  # Get details about this alert.
                        published = _parse_date(cve.get("published"))  # Figure out when it was first posted.
                        modified = _parse_date(cve.get("lastModified"))  # Figure out when it was last updated.
                        items.append({  # Add this alert to our basket with its details.
                            "id": cve.get("id", "N/A"),  # The alert’s unique name, or "N/A" if missing.
                            "description": cve.get("descriptions", [{}])[0].get("value", "No description"),  # What the alert is about.
                            "published_date": published,  # When it was posted.
                            "modified_date": modified  # When it was last changed.
                        })
                    logging.debug(f"Fetched {len(items)} items from NIST NVD")  # Write in the diary: "Got X alerts from NIST NVD."
                    return items  # Hand the basket of alerts back to Zentivox.
            except asyncio.TimeoutError:  # If the website takes too long (over 60 seconds).
                logging.warning(f"Timeout fetching {source_name} after {NIST_TIMEOUT}s")  # Diary: "Waited too long for NIST NVD."
                if not retry:  # If we haven’t tried again yet...
                    logging.info(f"Retrying {source_name} with {NIST_TIMEOUT}s timeout")  # Diary: "Trying again."
                    return await fetch_cve_data(cve_url, source_name, retry=True)  # Try one more time.
                return [{"id": "N/A", "title": f"{source_name} loading timed out", "link": cve_url, "published_date": None}]  # Give up and return a "timed out" message.
            except aiohttp.ClientError as e:  # If the website says "No" or has a problem.
                logging.error(f"Fetch error for {source_name}: {e}")  # Diary: "Something went wrong with NIST NVD."
                return []  # Come back with an empty basket.
            except Exception as e:  # If something totally unexpected happens.
                logging.error(f"Unexpected error in {source_name}: {e}")  # Diary: "Big problem with NIST NVD!"
                return []  # Come back with an empty basket.
    else:  # Instructions for CISA Alerts and Exploit-DB, which use news feeds (RSS).
        def fetch_feed():  # A mini-helper to grab the feed data.
            try:
                logging.debug(f"Fetching {source_name} from {cve_url} with feedparser")  # Diary: "Trying to get data from {source_name}."
                feed = feedparser.parse(cve_url)  # Read the news feed from the website.
                if feed.bozo:  # If the feed is broken or weird...
                    logging.warning(f"Feed parsing failed for {source_name}")  # Diary: "The feed from {source_name} is messed up."
                    return []  # Come back with an empty basket.
                items = []  # A basket for the alerts.
                for entry in feed.entries[:10]:  # Look at the first 10 items in the feed.
                    published = _parse_date(entry.published_parsed) if hasattr(entry, "published_parsed") else None  # Figure out when it was posted.
                    if source_name == "CISA Alerts":  # Special rules for CISA Alerts.
                        title = BeautifulSoup(entry.get("title", "N/A"), "html.parser").get_text()  # Clean up the title text.
                        items.append({  # Add this alert to the basket.
                            "id": entry.get("id", "N/A").split('/')[-1],  # A short ID from the link.
                            "title": title,  # The alert’s title.
                            "link": entry.get("link"),  # A web link to read more.
                            "published_date": published  # When it was posted.
                        })
                    elif source_name == "Exploit-DB":  # Special rules for Exploit-DB.
                        items.append({  # Add this alert to the basket.
                            "id": entry.get("title", "N/A").split(":")[0],  # The ID is the first part of the title.
                            "title": entry.get("title"),  # The full title.
                            "link": entry.get("link"),  # A web link to read more.
                            "published_date": published  # When it was posted.
                        })
                logging.debug(f"Fetched {len(items)} items from {source_name}")  # Diary: "Got X alerts from {source_name}."
                return items  # Hand the basket back.
            except Exception as e:  # If something goes wrong.
                logging.error(f"Error fetching {source_name} with feedparser: {e}")  # Diary: "Problem with {source_name} feed!"
                return []  # Come back with an empty basket.

        loop = asyncio.get_running_loop()  # Get Zentivox’s multitasking system ready.
        return await loop.run_in_executor(None, fetch_feed)  # Run the mini-helper and bring back the results.

async def fetch_news_data(news_url, source_name):
    """This helper grabs cybersecurity news articles from websites like Bleeping Computer or Krebs on Security for Zentivox."""
    async with aiohttp.ClientSession() as session:  # Opens a connection to the internet.
        try:
            async with session.get(news_url, timeout=aiohttp.ClientTimeout(total=DEFAULT_TIMEOUT)) as response:
                # Ask the website for data and wait up to 30 seconds.
                response.raise_for_status()  # Make sure the website says "OK."
                text = await response.text()  # Get the raw text from the website.
                feed = feedparser.parse(text)  # Turn the text into a news feed we can read.
                if feed.bozo and source_name == "Security Affairs":  # If the feed is broken and it’s Security Affairs...
                    feed = feedparser.parse(text)  # Try again (Security Affairs sometimes needs a second chance).
                if feed.bozo:  # If it’s still broken...
                    logging.warning(f"Feed parsing failed for {source_name}")  # Diary: "The feed from {source_name} is messed up."
                    return []  # Come back with an empty basket.
                items = []  # A basket for the news articles.
                for entry in feed.entries[:10]:  # Look at the first 10 articles in the feed.
                    published = _parse_date(entry.published_parsed) if hasattr(entry, "published_parsed") else None  # Figure out when it was posted.
                    items.append({  # Add this article to the basket.
                        "title": entry.get("title", "N/A"),  # The article’s headline.
                        "link": entry.get("link"),  # A web link to read the full story.
                        "published_date": published  # When it was posted.
                    })
                logging.debug(f"Fetched {len(items)} items from {source_name}")  # Diary: "Got X articles from {source_name}."
                return items  # Hand the basket back.
        except aiohttp.ClientError as e:  # If the website has a problem.
            logging.error(f"Fetch error for {source_name}: {e}")  # Diary: "Something went wrong with {source_name}."
            return []  # Come back with an empty basket.
        except Exception as e:  # If something totally unexpected happens.
            logging.error(f"Unexpected error in {source_name}: {e}")  # Diary: "Big problem with {source_name}!"
            return []  # Come back with an empty basket.

def _parse_date(date_input):
    """This helper figures out dates from messy text for Zentivox, like turning 'Feb 22, 2025' into something the program understands."""
    if isinstance(date_input, str):  # If the date is written as words or numbers...
        try:
            return date_parser.parse(date_input)  # Turn it into a proper date.
        except ValueError:  # If it’s too messy to understand...
            logging.warning(f"Failed to parse date: {date_input}")  # Diary: "Couldn’t figure out this date."
            return None  # Say "I don’t know this date."
    elif hasattr(date_input, "tm_year"):  # If the date is in a special feed format...
        return datetime.fromtimestamp(time.mktime(date_input))  # Turn it into a proper date.
    return None  # If it’s neither, say "I don’t know this date."

# --- State Management ---
# These helpers remember when Zentivox last checked for updates.

def load_state():
    """This helper looks in a file to see when Zentivox last checked for updates."""
    try:
        with open(STATE_FILE, "r") as f:  # Open the memory file (zentivox_state.json).
            return json.load(f)  # Read the last check times.
    except (FileNotFoundError, json.JSONDecodeError):  # If the file is missing or broken...
        return {"cve_last_check": 0, "news_last_check": 0}  # Start fresh with "never checked."

def save_state(state):
    """This helper saves the latest check times to a file so Zentivox remembers next time."""
    try:
        with open(STATE_FILE, "w") as f:  # Open the memory file (zentivox_state.json) to write.
            json.dump(state, f)  # Save the check times.
    except Exception as e:  # If something goes wrong...
        logging.error(f"Failed to save state: {e}")  # Diary: "Couldn’t save the memory file!"

# --- GUI Logic ---
# This is the main part of Zentivox that makes the window you see and interact with.

class Zentivox:
    """This is Zentivox itself—a window that shows cybersecurity alerts and news."""
    def __init__(self):
        # Set up the basics when Zentivox starts.
        self.window = tk.Tk()  # Create a new window.
        self.window.title("Zentivox Threat Intel Gathering")  # Call it "Zentivox."
        self.window.geometry("800x600")  # Make it 800 pixels wide and 600 pixels tall.
        self.loop = asyncio.new_event_loop()  # Set up a system to do many things at once.
        asyncio.set_event_loop(self.loop)  # Tell Zentivox to use this system.
        self.link_ranges_cve = []  # A list to remember where clickable links are for alerts.
        self.link_ranges_news = []  # A list to remember where clickable links are for news.
        self.running = True  # A flag to say "Zentivox is on."
        self.setup_ui()  # Build the window with buttons and text areas.
        self.window.protocol("WM_DELETE_WINDOW", self.on_closing)  # Tell the window what to do when you click "X."
        self.poll_async_tasks()  # Start a helper to keep things moving smoothly.

    def setup_ui(self):
        """This builds the Zentivox window with all its buttons and text boxes."""
        # Make a section for cybersecurity alerts.
        cve_frame = tk.Frame(self.window)  # A box to hold alert stuff.
        cve_frame.pack(pady=5, padx=10, fill=tk.BOTH, expand=True)  # Put it in the window with some space around it.
        tk.Label(cve_frame, text="CVE Alerts:", font=("Helvetica", 12, "bold")).pack(anchor=tk.W)  # Add a title "CVE Alerts" in big, bold text.

        self.cve_source_var = tk.StringVar(value="Select CVE Source")  # A way to remember which alert source you picked.
        cve_dropdown = ttk.Combobox(cve_frame, textvariable=self.cve_source_var, values=list(CVE_SOURCES.keys()), state="readonly")
        # A dropdown menu with alert sources like "NIST NVD."
        cve_dropdown.pack(anchor=tk.W)  # Put it in the window.
        cve_dropdown.bind("<<ComboboxSelected>>", lambda e: self.refresh_cve())  # When you pick one, update the alerts.

        self.cve_text = scrolledtext.ScrolledText(cve_frame, wrap=tk.WORD, height=10, state=tk.DISABLED)
        # A scrollable box to show alerts, 10 lines tall, locked until we add text.
        self.cve_text.pack(fill=tk.BOTH, expand=True)  # Fill the space with this box.
        self.cve_text.tag_config("link", foreground="blue", underline=True)  # Make links blue and underlined.
        self.cve_text.tag_config("bold", font=("Helvetica", 11, "bold"), foreground="black")  # Make some text bold and black.
        self.cve_text.bind("<Button-1>", lambda e: self.open_link(e, self.cve_text, self.link_ranges_cve))
        # When you click in this box, check if it’s a link to open.

        # Make a section for news articles.
        news_frame = tk.Frame(self.window)  # A box to hold news stuff.
        news_frame.pack(pady=5, padx=10, fill=tk.BOTH, expand=True)  # Put it in the window with some space.
        tk.Label(news_frame, text="Cybersecurity News:", font=("Helvetica", 12, "bold")).pack(anchor=tk.W)  # Add a title "Zentivox News" (changed from "Cybersecurity News").
        self.news_source_var = tk.StringVar(value="Select News Source")  # A way to remember which news source you picked.
        news_dropdown = ttk.Combobox(news_frame, textvariable=self.news_source_var, values=list(NEWS_SOURCES.keys()), state="readonly")
        # A dropdown menu with news sources like "Krebs on Security."
        news_dropdown.pack(anchor=tk.W)  # Put it in the window.
        news_dropdown.bind("<<ComboboxSelected>>", lambda e: self.refresh_news())  # When you pick one, update the news.

        self.news_text = scrolledtext.ScrolledText(news_frame, wrap=tk.WORD, height=10, state=tk.DISABLED)
        # A scrollable box to show news, 10 lines tall, locked until we add text.
        self.news_text.pack(fill=tk.BOTH, expand=True)  # Fill the space with this box.
        self.news_text.tag_config("link", foreground="blue", underline=True)  # Make links blue and underlined.
        self.news_text.tag_config("bold", font=("Helvetica", 11, "bold"), foreground="black")  # Make some text bold and black.
        self.news_text.bind("<Button-1>", lambda e: self.open_link(e, self.news_text, self.link_ranges_news))
        # When you click in this box, check if it’s a link to open.

        # Add buttons at the bottom.
        controls = tk.Frame(self.window)  # A box for buttons.
        controls.pack(pady=5)  # Put it in the window with some space.
        self.auto_refresh_var = tk.BooleanVar(value=False)  # A switch to turn auto-refresh on or off.
        tk.Checkbutton(controls, text="Auto-Refresh (5 min)", variable=self.auto_refresh_var, command=self.toggle_auto_refresh).pack(side=tk.LEFT, padx=5)
        # A checkbox to turn on auto-updates every 5 minutes.
        tk.Button(controls, text="Refresh Now", command=self.refresh_both).pack(side=tk.LEFT, padx=5)  # A button to update everything right now.
        tk.Button(controls, text="Generate Report", command=self.generate_report).pack(side=tk.LEFT, padx=5)  # A button to save what you see to a file.

        self.status_label = tk.Label(self.window, text="Zentivox Initialized. Select sources to start.")  # A message at the bottom saying what’s happening (changed from "Initialized...").
        self.status_label.pack(pady=5)  # Put it in the window with some space.

    def poll_async_tasks(self):
        """This keeps Zentivox running smoothly by checking for tasks every 0.1 seconds."""
        if self.running:  # If Zentivox is still on...
            self.loop.run_until_complete(asyncio.sleep(0))  # Let any background tasks finish quickly.
            self.window.after(100, self.poll_async_tasks)  # Check again in 0.1 seconds.

    async def refresh_cve_async(self):
        """This gets the latest cybersecurity alerts when you ask for them in Zentivox."""
        source = self.cve_source_var.get()  # See which alert source you picked.
        if source == "Select CVE Source":  # If you haven’t picked one yet...
            return  # Do nothing.
        self.status_label.config(text="Checking CVE updates...")  # Tell you "I’m checking alerts."
        data = await fetch_cve_data(CVE_SOURCES[source], source)  # Go get the alerts from the website.
        self.update_cve_text(data, source)  # Show the alerts in the window.
        state = load_state()  # Check when we last looked for alerts.
        state["cve_last_check"] = time.time()  # Remember this check time.
        save_state(state)  # Save it to the memory file.
        self.status_label.config(text=f"Zentivox CVE check: {datetime.now().strftime(DATE_FORMAT_DISPLAY)}")  # Update the message with the time (changed from "Last CVE check").

    async def refresh_news_async(self):
        """This gets the latest news articles when you ask for them in Zentivox."""
        source = self.news_source_var.get()  # See which news source you picked.
        if source == "Select News Source":  # If you haven’t picked one yet...
            return  # Do nothing.
        self.status_label.config(text="Checking news updates...")  # Tell you "I’m checking news."
        data = await fetch_news_data(NEWS_SOURCES[source], source)  # Go get the news from the website.
        self.update_news_text(data, source)  # Show the news in the window.
        state = load_state()  # Check when we last looked for news.
        state["news_last_check"] = time.time()  # Remember this check time.
        save_state(state)  # Save it to the memory file.
        self.status_label.config(text=f"Zentivox news check: {datetime.now().strftime(DATE_FORMAT_DISPLAY)}")  # Update the message with the time (changed from "Last news check").

    def refresh_cve(self):
        """This starts the alert update process when you pick a source in Zentivox."""
        asyncio.ensure_future(self.refresh_cve_async())  # Tell Zentivox to get alerts in the background.

    def refresh_news(self):
        """This starts the news update process when you pick a source in Zentivox."""
        asyncio.ensure_future(self.refresh_news_async())  # Tell Zentivox to get news in the background.

    async def refresh_both_async(self):
        """This updates both alerts and news at the same time in Zentivox."""
        self.status_label.config(text="Zentivox refreshing CVE and news...")  # Tell you "I’m updating everything" (changed from "Refreshing CVE and news").
        cve_source = self.cve_source_var.get()  # See which alert source you picked.
        news_source = self.news_source_var.get()  # See which news source you picked.

        cve_task = fetch_cve_data(CVE_SOURCES[cve_source], cve_source) if cve_source in CVE_SOURCES else asyncio.Future()
        # Start getting alerts if you picked a source, otherwise do nothing.
        news_task = fetch_news_data(NEWS_SOURCES[news_source], news_source) if news_source in NEWS_SOURCES else asyncio.Future()
        # Start getting news if you picked a source, otherwise do nothing.
        cve_data, news_data = await asyncio.gather(cve_task, news_task, return_exceptions=True)  # Wait for both to finish.

        if cve_source in CVE_SOURCES:  # If you picked an alert source...
            self.update_cve_text(cve_data, cve_source)  # Show the alerts.
            state = load_state()  # Check the last update time.
            state["cve_last_check"] = time.time()  # Save this check time.
            save_state(state)  # Update the memory file.

        if news_source in NEWS_SOURCES:  # If you picked a news source...
            self.update_news_text(news_data, news_source)  # Show the news.
            state = load_state()  # Check the last update time.
            state["news_last_check"] = time.time()  # Save this check time.
            save_state(state)  # Update the memory file.

        self.status_label.config(text=f"Zentivox last refresh: {datetime.now().strftime(DATE_FORMAT_DISPLAY)}")  # Tell you when everything was last updated (changed from "Last refresh").

    def refresh_both(self):
        """This starts updating both alerts and news when you click 'Refresh Now' in Zentivox."""
        asyncio.ensure_future(self.refresh_both_async())  # Tell Zentivox to update everything in the background.

    def update_cve_text(self, data, source):
        """This puts the cybersecurity alerts into the Zentivox window so you can see them."""
        self.cve_text.config(state=tk.NORMAL)  # Unlock the alert box so we can write in it.
        self.cve_text.delete("1.0", tk.END)  # Clear out any old alerts.
        self.link_ranges_cve = []  # Reset the list of clickable links.
        logging.debug(f"Processing {len(data)} items for {source} in update_cve_text")  # Diary: "Starting to show {X} alerts from {source}."
        for i, item in enumerate(data):  # Go through each alert one by one.
            try:
                logging.debug(f"Item {i+1} for {source}: {item}")  # Diary: "Working on alert number {i+1}."
                if source == "NIST NVD":  # Special way to show NIST NVD alerts.
                    self.cve_text.insert(tk.END, f"{source} Alert:\n", "bold")  # Write "NIST NVD Alert:" in bold.
                    self.cve_text.insert(tk.END, f"ID: {item.get('id', 'N/A')}\n", "bold")  # Show the alert’s ID in bold.
                    self.cve_text.insert(tk.END, f"Desc: {item.get('description', 'No description')[:150]}...\n")  # Show the first 150 characters of the description.
                    pub_date = item.get("published_date")  # Get when it was posted.
                    mod_date = item.get("modified_date")  # Get when it was last changed.
                    if pub_date:  # If we know the post date...
                        self.cve_text.insert(tk.END, f"Published Date: {pub_date.strftime(DATE_FORMAT_DISPLAY)}\n")  # Show it.
                    else:
                        self.cve_text.insert(tk.END, "Published Date: N/A\n")  # Say "N/A" if we don’t know.
                    if mod_date:  # If we know the change date...
                        self.cve_text.insert(tk.END, f"Modified Date: {mod_date.strftime(DATE_FORMAT_DISPLAY)}\n")  # Show it.
                    else:
                        self.cve_text.insert(tk.END, "Modified Date: N/A\n")  # Say "N/A" if we don’t know.
                else:  # Way to show CISA Alerts and Exploit-DB.
                    self.cve_text.insert(tk.END, f"{source} Alert:\n", "bold")  # Write "{source} Alert:" in bold.
                    self.cve_text.insert(tk.END, f"ID: {item.get('id', 'N/A')}\n", "bold")  # Show the alert’s ID in bold.
                    self.cve_text.insert(tk.END, f"Title: {item.get('title', 'N/A')}\n", "bold")  # Show the alert’s title in bold.
                    pub_date = item.get("published_date")  # Get when it was posted.
                    if pub_date:  # If we know the post date...
                        self.cve_text.insert(tk.END, f"Published Date: {pub_date.strftime(DATE_FORMAT_DISPLAY)}\n")  # Show it.
                    else:
                        self.cve_text.insert(tk.END, "Published Date: N/A\n")  # Say "N/A" if we don’t know.
                    if "link" in item:  # If there’s a web link...
                        start = self.cve_text.index(tk.INSERT)  # Mark where we’re about to add the link.
                        self.cve_text.insert(tk.END, f"Link: {item.get('link', 'N/A')}\n", "link")  # Show the link in blue.
                        end = self.cve_text.index(tk.INSERT)  # Mark where the link ends after adding it.
                        self.link_ranges_cve.append({"range": (start, end), "url": item["link"]})  # Save it so you can click it later.
                self.cve_text.insert(tk.END, "--------------------\n")  # Add a line of dashes to separate alerts.
            except Exception as e:  # If something goes wrong with this alert...
                logging.error(f"Error processing item {i+1} for {source}: {e}, Item: {item}")  # Diary: "Problem with alert {i+1}!"
                continue  # Skip it and move to the next alert.
        self.cve_text.config(state=tk.DISABLED)  # Lock the alert box again so you can’t edit it.

    def update_news_text(self, data, source):
        """This puts the news articles into the Zentivox window so you can see them."""
        self.news_text.config(state=tk.NORMAL)  # Unlock the news box so we can write in it.
        self.news_text.delete("1.0", tk.END)  # Clear out any old news.
        self.link_ranges_news = []  # Reset the list of clickable links.
        for item in data:  # Go through each news article one by one.
            self.news_text.insert(tk.END, "News:\n", "bold")  # Write "News:" in bold.
            self.news_text.insert(tk.END, f"Title: {item.get('title', 'N/A')}\n", "bold")  # Show the article’s headline in bold.
            pub_date = item.get("published_date")  # Get when it was posted.
            if pub_date:  # If we know the post date...
                self.news_text.insert(tk.END, f"Published Date: {pub_date.strftime(DATE_FORMAT_DISPLAY)}\n")  # Show it.
            else:
                self.news_text.insert(tk.END, "Published Date: N/A\n")  # Say "N/A" if we don’t know.
            self.news_text.insert(tk.END, f"Source: {source}\n")  # Show where it came from.
            start = self.news_text.index(tk.INSERT)  # Mark where we’re about to add the link.
            self.news_text.insert(tk.END, f"Link: {item.get('link', 'N/A')}\n", "link")  # Show the link in blue.
            end = self.news_text.index(tk.INSERT)  # Mark where the link ends after adding it.
            self.link_ranges_news.append({"range": (start, end), "url": item["link"]})  # Save it so you can click it later.
            self.news_text.insert(tk.END, "--------------------\n")  # Add a line of dashes to separate articles.
        self.news_text.config(state=tk.DISABLED)  # Lock the news box again so you can’t edit it.

    def open_link(self, event, text_widget, link_ranges):
        """This opens a web browser when you click a link in the Zentivox window."""
        index = text_widget.index(f"@{event.x},{event.y}")  # Figure out where you clicked in the text box.
        for link in link_ranges:  # Check each saved link.
            start, end = link["range"]  # Get the start and end spots of this link.
            if text_widget.compare(start, "<=", index) and text_widget.compare(index, "<", end):  # If you clicked inside this link...
                webbrowser.open_new(link["url"])  # Open your web browser to that link.
                logging.debug(f"Opening link: {link['url']}")  # Diary: "Clicked a link!"
                break  # Stop looking at other links.

    def generate_report(self):
        """This saves what you see in the Zentivox window to a file you can keep."""
        report = {"cve_alerts": [], "news": []}  # A basket to hold alerts and news for the file.
        cve_text = self.cve_text.get("1.0", tk.END).strip().split("--------------------\n")  # Get all the alert text and split it by dashes.
        for block in cve_text:  # Go through each alert.
            if not block.strip():  # If it’s empty...
                continue  # Skip it.
            entry = {}  # A mini-basket for this alert’s details.
            lines = block.strip().split("\n")  # Break it into lines like "ID: something."
            for line in lines:  # Look at each line.
                if ": " in line:  # If it’s a "label: value" line...
                    key, value = line.split(": ", 1)  # Split it into the label and the value.
                    entry[key] = value  # Save it in the mini-basket.
            if entry:  # If we found something...
                report["cve_alerts"].append(entry)  # Add it to the big basket.

        news_text = self.news_text.get("1.0", tk.END).strip().split("--------------------\n")  # Get all the news text and split it by dashes.
        for block in news_text:  # Go through each news article.
            if not block.strip():  # If it’s empty...
                continue  # Skip it.
            entry = {}  # A mini-basket for this article’s details.
            lines = block.strip().split("\n")  # Break it into lines like "Title: something."
            for line in lines:  # Look at each line.
                if ": " in line:  # If it’s a "label: value" line...
                    key, value = line.split(": ", 1)  # Split it into the label and the value.
                    entry[key] = value  # Save it in the mini-basket.
            if entry:  # If we found something...
                report["news"].append(entry)  # Add it to the big basket.

        file_path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON files", "*.json")])
        # Ask you where to save the file, suggesting a ".json" ending.
        if file_path:  # If you picked a place...
            with open(file_path, "w") as f:  # Open that file to write.
                json.dump(report, f, indent=4)  # Save the basket in a neat format.
            logging.info(f"Zentivox report saved to {file_path}")  # Diary: "Saved the report here!" (changed from "Report saved").

    async def auto_refresh_loop(self):
        """This keeps checking for updates every 5 minutes if you turned on auto-refresh in Zentivox, waiting until 5 minutes since last check."""
        while self.running and self.auto_refresh_var.get():  # As long as Zentivox is on and auto-refresh is checked...
            state = load_state()  # Check when we last updated.
            last_check = max(state.get("cve_last_check", 0), state.get("news_last_check", 0))  # Get the most recent update time.
            now = time.time()  # What time is it now?
            time_since_last = now - last_check  # How long since the last update?
            if time_since_last < NOTIFICATION_INTERVAL_SECONDS:  # If it’s been less than 5 minutes...
                wait_time = NOTIFICATION_INTERVAL_SECONDS - time_since_last  # How much longer to wait?
                logging.debug(f"Waiting {wait_time:.1f} seconds until next Zentivox refresh")  # Diary: "Waiting a bit before refreshing."
                await asyncio.sleep(wait_time)  # Wait until it’s been 5 minutes.
            await self.refresh_both_async()  # Update everything after waiting.
            logging.debug(f"Zentivox auto-refresh completed at {datetime.now().strftime(DATE_FORMAT_DISPLAY)}")  # Diary: "Just refreshed!"

    def toggle_auto_refresh(self):
        """This turns auto-refresh on or off when you click the checkbox in Zentivox."""
        if self.auto_refresh_var.get():  # If you checked the box...
            asyncio.ensure_future(self.auto_refresh_loop())  # Start the auto-update loop in the background.

    def on_closing(self):
        """This cleans up and closes Zentivox when you click the 'X' button."""
        print("Zentivox is closing")  # Say "Goodbye" in the terminal
        self.running = False  # Tell Zentivox "We’re done."
        self.loop.stop()  # Stop the multitasking system.
        self.window.destroy()  # Close the window.
        sys.exit(0)  # Shut down the program completely.

    def run(self):
        """This starts Zentivox and keeps the window open until close it."""
        self.window.mainloop()  # Keep the window running and listening for your clicks.

# This is the starting point of Zentivox.
if __name__ == "__main__":
    try:
        app = Zentivox()  # Create Zentivox.
        app.run()  # Start Zentivox and show the window.
    except KeyboardInterrupt:  # If press Ctrl+C to stop it...
        print("\nZentivox is closing")  # Say "Goodbye" in the terminal
        logging.info("Zentivox terminated via keyboard interrupt")  # Diary: "You stopped me with Ctrl+C"
        sys.exit(0)  # Shut down nicely.
    except Exception as e:  # If something big goes wrong...
        logging.error(f"Zentivox crashed: {e}")  # Diary: "I crashed because of this problem!"
        sys.exit(1)  # Shut down with an error signal.
