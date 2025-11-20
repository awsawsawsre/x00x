
import smtplib
import random
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from datetime import datetime, timedelta
import json
import os
import time
import sys


from_addresses = []
email_subjects = []

DATE_FORMAT = "%m/%d/%Y"
filename = ""
BASE_LIMIT = 50
STATE_FILE = "email_state.json"

def load_state():
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, "r", encoding="utf-8") as f:
                state = json.load(f)
        except json.JSONDecodeError:
            state = {"sender_usage": {}, "last_index": 0}
    else:
        state = {"sender_usage": {}, "last_index": 0}

    su = state.setdefault("sender_usage", {})
    for addr in from_addresses:
        su.setdefault(addr, {
            "count": 0,
            "reset_time": None,  
            "limit": BASE_LIMIT,
            "exhausted": False
        })

    return state

def save_state(state):
    tmp = STATE_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2, default=str)
    os.replace(tmp, STATE_FILE)

def parse_reset_time(val):
    if not val:
        return None
    try:
        return datetime.fromisoformat(val)
    except Exception:
        return None

def get_contacts(filename):
    """Read email addresses from file (one per line)."""
    emails = []
    with open(filename, mode='r', encoding='utf-8') as contacts_file:
        for a_contact in contacts_file:
            emails.append(a_contact.strip())
    return emails      

def reset_if_needed(addr, usage):
    now = datetime.now()

    if usage["reset_time"] is None:
        usage["reset_time"] = (now + timedelta(hours=24)).isoformat()
        return

    reset_time = parse_reset_time(usage["reset_time"])
    if reset_time and now >= reset_time:
        if usage.get("exhausted", False):
            usage["limit"] = int(usage.get("limit", BASE_LIMIT)) + 50
        usage["count"] = 0
        usage["exhausted"] = False
        usage["reset_time"] = (now + timedelta(hours=24)).isoformat()

def pick_sender(state):
    """Pick the next sender randomly among those under limit. If none, return soonest reset."""
    available = []
    next_reset_times = []

    for addr, usage in state["sender_usage"].items():
        reset_if_needed(addr, usage)

        if usage["count"] < usage["limit"]:
            available.append(addr)
        else:
            if not usage.get("exhausted", False):
                usage["exhausted"] = True
            rt = parse_reset_time(usage.get("reset_time"))
            if rt:
                next_reset_times.append(rt)

    if not available:
        soonest = min(next_reset_times) if next_reset_times else datetime.now() + timedelta(hours=24)
        return None, soonest

    chosen = random.choice(available)
    cu = state["sender_usage"][chosen]
    cu["count"] += 1
    if cu["count"] >= cu["limit"]:
        cu["exhausted"] = True
    return chosen, None

def countdown_wait(wait_until):
    """Show live countdown until reset in a single line."""
    while True:
        remaining = (wait_until - datetime.now()).total_seconds()
        if remaining <= 0:
            sys.stdout.write("\rReset reached! Resuming...            \n")
            sys.stdout.flush()
            break
        hrs, remainder = divmod(int(remaining), 3600)
        mins, secs = divmod(remainder, 60)
        sys.stdout.write(f"\rAll senders exhausted. Next reset in {hrs:02d}:{mins:02d}:{secs:02d}")
        sys.stdout.flush()
        time.sleep(1)


def main():
    state = load_state()
    emails = get_contacts("")  

    idx = state["last_index"]
    while idx < len(emails):
        email = emails[idx]
        fromaddr, wait_until = pick_sender(state)

        if fromaddr is None:
            save_state(state)
            countdown_wait(wait_until)
            continue  
            
            for addr, usage in state["sender_usage"].items():
                reset_if_needed(addr, usage)
            save_state(state)
            continue  

    
        email_subject = random.choice(email_subjects) if email_subjects else "No Subject"
        email_content_file = f"./html/variant_{random.randint(1, 11)}.txt"

    
        name_part = fromaddr.split("<")[0].strip()

        msg = MIMEMultipart()
        msg["From"] = fromaddr
        msg["To"] = email
        msg["Subject"] = email_subject
        msg["Reply-To"] = ""  

       
        try:
            with open(email_content_file, "r", encoding="utf-8") as textfile:
                content = textfile.read()
        except FileNotFoundError:
            print(f"Content file {email_content_file} not found, skipping {email}")
            idx += 1
            continue

        body = content.replace("{name_part}", name_part)
        msg.attach(MIMEText(body, "html"))

        
        if filename:
            with open(filename, "rb") as attachment:
                p = MIMEBase("application", "octet-stream")
                p.set_payload(attachment.read())
                encoders.encode_base64(p)
                p.add_header("Content-Disposition", f"attachment; filename={os.path.basename(filename)}")
                msg.attach(p)

        
        try:
            smtp_server = ""
            smtp_port = 
            smtp_user = ""
            smtp_pass = ""

            server = smtplib.SMTP(smtp_server, smtp_port)
            server.starttls()
            server.login(smtp_user, smtp_pass)
            server.sendmail(fromaddr, email, msg.as_string())
            server.quit()

            usage = state["sender_usage"][fromaddr]
            print(f"✅ Email sent to {email} from {name_part} "
                  f"(used {usage['count']}/{usage['limit']}, "
                  f"resets at {usage['reset_time']}) "
                  f"with subject: {msg['Subject']}")

        except Exception as e:
            print(f"❌ Failed to send to {email}: {e}")
            time.sleep(5)
            continue

        idx += 1
        state["last_index"] = idx
        save_state(state)

    print(" All emails processed!")

if __name__ == "__main__":
    main()


