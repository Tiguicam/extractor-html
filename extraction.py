import os
import sys
import threading
import time
import base64
from io import BytesIO
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup, Comment, NavigableString
from PIL import Image
from playwright.sync_api import sync_playwright

import tkinter as tk
from tkinter import ttk, messagebox, filedialog

############################################
# GLOBALS
############################################
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123 Safari/537.36"
)
SESSION = requests.Session()

# Change cwd to script / exec folder (PyInstaller‑safe)
EXEC_DIR = os.path.dirname(sys.executable if getattr(sys, "frozen", False) else os.path.abspath(__file__))
os.chdir(EXEC_DIR)

############################################
# UTILITY FUNCTIONS
############################################

def robust_get(url: str, timeout: int = 12):
    try:
        r = SESSION.get(url, headers={"User-Agent": USER_AGENT}, timeout=timeout)
        r.raise_for_status()
        return r, None
    except requests.exceptions.RequestException as e:
        return None, e


def load_config(path: str = "config.txt"):
    cfg = {k: [] for k in ("EXCLUDE_TAGS", "EXCLUDE_CLASSES", "EXCLUDE_KEYWORDS", "EXCLUDE_IDS")}
    if not os.path.exists(path):
        return cfg
    with open(path, encoding="utf-8") as f:
        for line in f:
            if ":" not in line:
                continue
            key, val = line.split(":", 1)
            key = key.strip().upper()
            if key in cfg:
                cfg[key] = [x.strip() for x in val.split(",") if x.strip()]
    return cfg


def image_to_datauri(url: str):
    if url.startswith("data:image"):
        return url
    if url.lower().endswith((".svg", ".gif")):
        return url  # don’t embed vector / gif
    resp, err = robust_get(url)
    if err:
        print("IMG fetch error", url, err)
        return None
    try:
        img = Image.open(BytesIO(resp.content))
        b = BytesIO()
        img.save(b, format=img.format or "PNG")
        return f"data:image/{(img.format or 'png').lower()};base64,{base64.b64encode(b.getvalue()).decode()}"
    except Exception as e:
        print("PIL error", url, e)
        return None


def is_hidden(tag):
    style = tag.get("style", "")
    if any(x in style for x in ("display: none", "visibility: hidden")):
        return True
    return "hidden" in tag.get("class", []) or tag.has_attr("hidden")

############################################
# DOM PARSER
############################################

def walk_dom(node, fh, base, cfg, embed_img: bool):
    for child in node.children:
        if isinstance(child, Comment):
            continue
        if isinstance(child, NavigableString):
            txt = child.strip()
            if txt and not any(k.lower() in txt.lower() for k in cfg["EXCLUDE_KEYWORDS"]):
                fh.write(f'<span class="raw-text">{txt}</span>\n')
            continue
        if not child.name or child.name in cfg["EXCLUDE_TAGS"] or is_hidden(child):
            continue
        if child.get("id") in cfg["EXCLUDE_IDS"]:
            continue

        if child.name == "img" and embed_img:
            src = (child.get("data-src") or child.get("srcset") or child.get("src") or "")
            if " " in src:
                src = src.split(" ")[0]
            abs_src = urljoin(base, src)
            alt = child.get("alt", "<em>Alt manquant</em>")
            data_uri = image_to_datauri(abs_src) or abs_src
            fh.write(f'<div class="image"><img src="{data_uri}" alt="{alt}"/><div><strong>ALT :</strong> {alt}</div></div>')
        elif child.name in {"h1", "h2", "h3", "h4", "h5", "h6"}:
            txt = child.get_text(strip=True)
            if txt and not any(k.lower() in txt.lower() for k in cfg["EXCLUDE_KEYWORDS"]):
                tag = child.name.upper()
                fh.write(f"<div class='heading-{tag}'><strong>{tag} : {txt}</strong></div>\n")
        elif child.name == "p":
            txt = child.get_text(strip=True)
            if txt and not any(k.lower() in txt.lower() for k in cfg["EXCLUDE_KEYWORDS"]):
                fh.write(f"<p>{txt}</p>\n")
        else:
            walk_dom(child, fh, base, cfg, embed_img)

############################################
# PLAYWRIGHT FETCHER
############################################

def fetch_rendered(url):
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page(user_agent=USER_AGENT)
        page.goto(url, timeout=30000)
        page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
        time.sleep(2)
        html = page.content()
        browser.close()
        return html

############################################
# EXTRACTION LOOP
############################################

def extract(urls, cfg, js, embed_img, prog, lbl):
    css = """
body{font-family:Arial,sans-serif;font-size:16px;line-height:1.6;color:#000}
.url-section{color:#006400;font-size:14px;font-weight:bold;margin:10px 0}
.title{color:#4B0082;font-size:16px;font-weight:bold;margin:5px 0}
.meta{color:#4B0082;font-size:16px;margin:5px 0}
hr{border:0;border-top:2px solid #4B0082;margin:10px 0}
.heading-H1{color:#00008B;font-size:16px;margin:8px 0}
.heading-H2{color:#4169E1;font-size:14px;margin:7px 0}
.heading-H3{color:#6495ED;font-size:13px;margin:6px 0}
.heading-H4{color:#6495ED;font-size:12px;margin:5px 0}
.heading-H5,.heading-H6{color:#6495ED;font-size:12px;margin:5px 0}
p{font-size:11px;margin:5px 0;color:#000}
.image img{max-width:300px;height:auto;margin:5px 0;border:1px solid #ccc}
.image div{font-size:12px;margin-top:3px}
.raw-text{display:inline-block;margin:2px 4px;color:#000}
"""

    with open("output.html", "w", encoding="utf-8") as fh:
        fh.write(f"<!doctype html><html><head><meta charset='utf-8'><style>{css}</style></head><body>")

    total = len(urls)
    for idx, u in enumerate(urls, 1):
        prog["value"] = idx
        lbl.config(text=f"{idx*100//total} %")
        lbl.update()
        with open("output.html", "a", encoding="utf-8") as fh:
            fh.write(f"<div class='url'>URL : {u}</div>")
            try:
                html = fetch_rendered(u) if js else robust_get(u)[0].text
            except Exception as e:
                fh.write(f"<p>Erreur chargement : {e}</p>")
                continue
            soup = BeautifulSoup(html, "html.parser")
            for tag in soup(["script", "style"]):
                tag.decompose()
            title = soup.find("title")
            fh.write("<hr>")
            if title:
                fh.write(f"<div class='title'>Title : {title.get_text(strip=True)}</div>")
            desc = soup.find("meta", attrs={"name": "description"})
            if desc and desc.get("content"):
                fh.write(f"<div class='meta'>Meta Description : {desc['content']}</div>")
            fh.write("<hr>")
            body = soup.body
            if body:
                walk_dom(body, fh, u, cfg, embed_img)
            else:
                fh.write("<p>Aucun body</p>")

    with open("output.html", "a", encoding="utf-8") as fh:
        fh.write("</body></html>")

############################################
# GUI
############################################

def pick(text):
    fp = filedialog.askopenfilename(filetypes=[("Text", "*.txt"), ("All", "*.*")])
    if fp:
        with open(fp, encoding="utf-8") as f:
            text.delete("1.0", tk.END)
            text.insert(tk.END, f.read())
def show_examples():
    example = (
        "EXCLUDE_TAGS: header, footer, nav\n"
        "EXCLUDE_CLASSES: banner, cookie, ads\n"
        "EXCLUDE_KEYWORDS: newsletter, login, inscription\n"
        "EXCLUDE_IDS: popup, promo\n"
        "\n"
        "# Chaque ligne suit le format  CLE: valeur1, valeur2, ...\n"
        "# → Copie‑colle et adapte selon ton site ;-)\n"
    )
    top = tk.Toplevel()
    top.title("Exemple de config.txt")
    top.configure(bg="white")
    tk.Label(top, text="Exemple de contenu pour config.txt", bg="white",
             font=("Arial", 11, "bold")).pack(pady=(10, 5))
    txt = tk.Text(top, width=60, height=10, bg="#f5f5f5")
    txt.insert(tk.END, example)
    txt.config(state="disabled")
    txt.pack(padx=10, pady=(0, 10))
    
def main_gui():
    root = tk.Tk(); root.title("Extractor Playwright"); root.configure(bg="white")

    f1 = tk.Frame(root, bg="white"); f1.pack(padx=10, pady=4, fill="x")
    tk.Label(f1, text="URLs (one per line):", bg="white").pack(anchor="w")
    txt_urls = tk.Text(f1, width=70, height=8); txt_urls.pack(side="left")
    tk.Button(f1, text="Browse", command=lambda: pick(txt_urls)).pack(side="left", padx=5)

    f2 = tk.Frame(root, bg="white"); f2.pack(padx=10, pady=4, fill="x")
    tk.Label(f2, text="Config (optional):", bg="white").pack(anchor="w")
    txt_cfg = tk.Text(f2, width=70, height=6); txt_cfg.pack(side="left")
    tk.Button(f2, text="Browse", command=lambda: pick(txt_cfg)).pack(side="left", padx=5)
    tk.Button(f2, text="Exemples config", command=show_examples).pack(side="left", padx=5)
    opts = tk.Frame(root, bg="white"); opts.pack(pady=6)
    use_js = tk.BooleanVar()
    tk.Checkbutton(opts, text="JavaScript rendering (Playwright)", variable=use_js, bg="white").pack(side="left", padx=8)
    embed_img = tk.BooleanVar(value=True)
    tk.Checkbutton(opts, text="Embed images", variable=embed_img, bg="white").pack(side="left", padx=8)

    prog = ttk.Progressbar(root, length=300, mode="determinate")
    pct = ttk.Label(root, text="0 %")

    def run():
        urls = [u.strip() for u in txt_urls.get("1.0", tk.END).splitlines() if u.strip()]
        if not urls:
            messagebox.showerror("Erreur", "Aucune URL")
            return
        with open("config.txt", "w", encoding="utf-8") as f:
            f.write(txt_cfg.get("1.0", tk.END))
        cfg = load_config()
        prog["maximum"] = len(urls); prog.pack(pady=4); pct.pack()
        def worker():
            extract(urls, cfg, use_js.get(), embed_img.get(), prog, pct)
            prog.pack_forget(); pct.pack_forget()
            messagebox.showinfo("OK", "Extraction terminée (output.html)")
        threading.Thread(target=worker, daemon=True).start()

    tk.Button(root, text="Start", command=run, bg="#e0e0e0").pack(pady=8)
    tk.Button(root, text="Quit", command=root.destroy, bg="#e0e0e0").pack(pady=(0,10))
    root.mainloop()

if __name__ == "__main__":
    main_gui()
