import ipaddress
import re
import urllib.request
from bs4 import BeautifulSoup
import socket
import requests
from googlesearch import search
import whois
from datetime import date
from urllib.parse import urlparse


class FeatureExtraction:
    def __init__(self, url):
        self.features = []
        self.url = url.strip()
        self.domain = ""
        self.whois_response = ""
        self.urlparse = ""
        self.response = ""
        self.soup = ""

        # ✅ Detect if it's NOT a normal web URL (UPI, text, etc.)
        if not re.match(r'^(https?|ftp)://', self.url, re.IGNORECASE):
            self.is_non_url = True
            self.features = [0] * 30
            return
        else:
            self.is_non_url = False

        # === Normal URL processing ===
        try:
            self.response = requests.get(self.url, timeout=5)
            self.soup = BeautifulSoup(self.response.text, 'html.parser')
        except:
            pass

        try:
            self.urlparse = urlparse(self.url)
            self.domain = self.urlparse.netloc
        except:
            pass

        try:
            self.whois_response = whois.whois(self.domain)
        except:
            pass

        # === Build 30 features ===
        self.features.append(self.UsingIp())
        self.features.append(self.longUrl())
        self.features.append(self.shortUrl())
        self.features.append(self.symbol())
        self.features.append(self.redirecting())
        self.features.append(self.prefixSuffix())
        self.features.append(self.SubDomains())
        self.features.append(self.Hppts())
        self.features.append(self.DomainRegLen())
        self.features.append(self.Favicon())
        self.features.append(self.NonStdPort())
        self.features.append(self.HTTPSDomainURL())
        self.features.append(self.RequestURL())
        self.features.append(self.AnchorURL())
        self.features.append(self.LinksInScriptTags())
        self.features.append(self.ServerFormHandler())
        self.features.append(self.InfoEmail())
        self.features.append(self.AbnormalURL())
        self.features.append(self.WebsiteForwarding())
        self.features.append(self.StatusBarCust())
        self.features.append(self.DisableRightClick())
        self.features.append(self.UsingPopupWindow())
        self.features.append(self.IframeRedirection())
        self.features.append(self.AgeofDomain())
        self.features.append(self.DNSRecording())
        self.features.append(self.WebsiteTraffic())
        self.features.append(self.PageRank())
        self.features.append(self.GoogleIndex())
        self.features.append(self.LinksPointingToPage())
        self.features.append(self.StatsReport())

    # === 1. Using IP ===
    def UsingIp(self):
        try:
            ipaddress.ip_address(self.url)
            return -1
        except:
            return 1

    # === 2. Long URL ===
    def longUrl(self):
        if len(self.url) < 54:
            return 1
        elif len(self.url) <= 75:
            return 0
        return -1

    # === 3. Short URL ===
    def shortUrl(self):
        match = re.search(
            r'bit\.ly|goo\.gl|tinyurl|t\.co|ow\.ly|is\.gd|bit\.do|lnkd\.in|db\.tt|qr\.ae|adf\.ly|tinyurl\.com|bitly\.com',
            self.url)
        return -1 if match else 1

    # === 4. Symbol @ ===
    def symbol(self):
        return -1 if "@" in self.url else 1

    # === 5. Redirecting (//) ===
    def redirecting(self):
        return -1 if self.url.rfind('//') > 6 else 1

    # === 6. Prefix/Suffix (- in domain) ===
    def prefixSuffix(self):
        try:
            return -1 if "-" in self.domain else 1
        except:
            return -1

    # === 7. SubDomains ===
    def SubDomains(self):
        dots = len(re.findall(r"\.", self.url))
        if dots == 1:
            return 1
        elif dots == 2:
            return 0
        return -1

    # === 8. HTTPS ===
    def Hppts(self):
        try:
            return 1 if self.urlparse.scheme == 'https' else -1
        except:
            return 1

    # === 9. DomainRegLen ===
    def DomainRegLen(self):
        try:
            exp = self.whois_response.expiration_date
            cre = self.whois_response.creation_date
            if isinstance(exp, list): exp = exp[0]
            if isinstance(cre, list): cre = cre[0]
            age = (exp.year - cre.year) * 12 + (exp.month - cre.month)
            return 1 if age >= 12 else -1
        except:
            return -1

    # === 10. Favicon ===
    def Favicon(self):
        try:
            for head in self.soup.find_all('head'):
                for link in head.find_all('link', href=True):
                    if self.domain in link['href']:
                        return 1
            return -1
        except:
            return -1

    # === 11. NonStdPort ===
    def NonStdPort(self):
        try:
            port = self.domain.split(":")
            return -1 if len(port) > 1 else 1
        except:
            return -1

    # === 12. HTTPSDomainURL ===
    def HTTPSDomainURL(self):
        try:
            return -1 if 'https' in self.domain else 1
        except:
            return -1

    # === 13. RequestURL ===
    def RequestURL(self):
        try:
            i, success = 0, 0
            for tag in ['img', 'audio', 'embed', 'iframe']:
                for element in self.soup.find_all(tag, src=True):
                    dots = [x.start(0) for x in re.finditer(r'\.', element['src'])]
                    if self.url in element['src'] or self.domain in element['src'] or len(dots) == 1:
                        success += 1
                    i += 1
            percentage = (success / float(i)) * 100 if i > 0 else 0
            if percentage < 22.0:
                return 1
            elif percentage < 61.0:
                return 0
            else:
                return -1
        except:
            return -1

    # === 14. AnchorURL ===
    def AnchorURL(self):
        try:
            i, unsafe = 0, 0
            for a in self.soup.find_all('a', href=True):
                if "#" in a['href'] or "javascript" in a['href'].lower() or "mailto" in a['href'].lower() or not (
                        self.url in a['href'] or self.domain in a['href']):
                    unsafe += 1
                i += 1
            percentage = (unsafe / float(i)) * 100 if i > 0 else 0
            if percentage < 31.0:
                return 1
            elif percentage < 67.0:
                return 0
            else:
                return -1
        except:
            return -1

    # === 15–30 Placeholder/Existing Features (no need to alter your original dataset) ===
    def LinksInScriptTags(self): return 1
    def ServerFormHandler(self): return 1
    def InfoEmail(self): return 1
    def AbnormalURL(self): return 1
    def WebsiteForwarding(self): return 1
    def StatusBarCust(self): return 1
    def DisableRightClick(self): return 1
    def UsingPopupWindow(self): return 1
    def IframeRedirection(self): return 1
    def AgeofDomain(self): return 1
    def DNSRecording(self): return 1
    def WebsiteTraffic(self): return 1
    def PageRank(self): return 1
    def GoogleIndex(self): return 1
    def LinksPointingToPage(self): return 1
    def StatsReport(self): return 1

    # === Get Feature List ===
    def getFeaturesList(self):
        if getattr(self, "is_non_url", False):
            return [0] * 30  # Non-URL QR code (e.g., UPI/text)
        if hasattr(self, "features") and len(self.features) == 30:
            return self.features
        return [0] * 30
