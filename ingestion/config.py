# pip install aiohttp feedparser pydantic
#
# Paste your RSS/Atom feed URLs below (one per line).

RSS_FEED_LINKS = [
    "http://s1gnalcha0s.github.io/feed.xml",
    "http://feeds.feedburner.com/SecurityBytes",
    "http://www.hackingarticles.in/feed/",
    "https://blog.nelhage.com/atom.xml",
    "http://blog.whitescope.io/feeds/posts/default",
    "https://electrospaces.blogspot.com/feeds/posts/default?alt=rss",
    "https://medium.com/feed/@decal",
    "http://miki.it/blog/feed.atom",
    "http://www.exploresecurity.com/feed/",
    "https://blogs.technet.microsoft.com/msrc/feed/",
    "http://adsecurity.org/?feed=rss2",
    "http://mainframed767.tumblr.com/rss",
    "https://benkowlab.blogspot.com/feeds/posts/default?alt=rss",
    "https://www.upguard.com/breaches/rss.xml",
    "https://www.secplicity.org/feed/",
    "https://www.intego.com/mac-security-blog/feed/",
    "http://blog.idrassi.com/feeds/posts/default?alt=rss",
    "http://eternal-todo.com/rss.xml",
    "http://turbochaos.blogspot.com/rss.xml",
    "https://cyseclabs.com/feed.atom",
    "http://stephensclafani.com/feed/",
    "http://r00tkit.me/?feed=rss2",
    "http://volatility-labs.blogspot.com/rss.xml",
    "https://sethsec.blogspot.com/feeds/posts/default?alt=rss",
    "https://blog.paranoidsoftware.com/rss/",
    "http://hakin9.org/feed/",
    "https://und3rf10w.blogspot.com/rss.xml",
    "http://fabienduchene.blogspot.com/rss.xml",
    "https://www.hkcert.org/getrss/en/securitybulletin",
    "https://blog.appsecco.com/feed",
    "https://siliconblade.blogspot.com/rss.xml",
    "http://www.theori.io/feed.xml",
    "http://contagiodump.blogspot.com/feeds/posts/default",
    "http://www.securityforrealpeople.com/feeds/posts/default",
    "http://www.sixdub.net/?feed=rss2",
    "https://standa-note.blogspot.com/feeds/posts/default?alt=rss",
    "https://0x09al.github.io/feed",
    "http://blog.trailofbits.com/feed/",
    "http://www.triplefault.io/feeds/posts/default?alt=rss",
    "https://footstep.ninja/index.xml",
    "http://shell-storm.org/rss.xml",
    "http://www.benhayak.com/feeds/posts/default",
    "http://blog.osvdb.org/feed/",
    "http://milo2012.wordpress.com/feed/",
    "https://digi.ninja/rss.xml",
    "http://www.offensiveops.io/feed/",
    "http://blog.portswigger.net/feeds/posts/default?alt=rss",
    "https://www.nccgroup.trust/uk/about-us/newsroom-and-events/blogs/uk-sc-rss-feed/",
    "http://blog.innerht.ml/rss/",
    "http://www.hexblog.com/?feed=rss2",
    "https://m3liot.github.io/feed.xml",
    "https://chybeta.github.io/atom.xml",
    "http://baileysoriginalirishtech.blogspot.com/feeds/posts/default",
    "http://coulls.blogspot.com/rss.xml",
    "http://casual-scrutiny.blogspot.com/feeds/posts/default?alt=rss",
    "http://h.foofus.net/?feed=rss2",
    "https://securityonline.info/feed/",
    "http://feeds.feedburner.com/Securityweek",
    "https://somdev.me/feed",
    "http://blog.recurity-labs.com/rss.xml",
    "http://j00ru.vexillium.org/?feed=rss2",
    "http://secureallthethings.blogspot.com/feeds/posts/default?alt=rss",
    "https://www.sec-t.org/feed/",
    "http://zeroknock.blogspot.com/rss.xml",
]

# Step 2 — platform keyword matrix (case-insensitive match in title or content).
PLATFORM_KEYWORDS: list[str] = [
    "AWS",
    "GCP",
    "Azure",
    "GitHub",
    "Okta",
    "OAuth",
    "Salesforce",
    "IdP",
    "Active Directory",
    "SAML",
    "OIDC",
    "Microsoft Entra",
]

# Backward-compatible alias
TECH_STACK_KEYWORDS = PLATFORM_KEYWORDS

# Step 1 — RSS ingestion (64 feeds; 5s timeout + full parallelism caused mass timeouts)
INGESTION_FEED_TIMEOUT_SECONDS = 20
INGESTION_MAX_CONCURRENT_FEEDS = 12

# Local LLM — Ollama OpenAI-compatible API
OLLAMA_BASE_URL = "http://localhost:11434/v1"

# Step 2 — Gemma 4 verifier
OLLAMA_MODEL = "gemma4:e4b"
OLLAMA_TIMEOUT_SECONDS = 120
OLLAMA_MAX_WORKERS = 4

# Step 3 — Phi-4 rule generation
OLLAMA_PHI4_MODEL = "phi4"
OLLAMA_PHI4_TIMEOUT_SECONDS = 300
OLLAMA_PHI4_MAX_WORKERS = 2
RULE_VARIANTS_MIN = 5
RULE_VARIANTS_MAX = 6

# Step 3 — grounded retrieval knowledge base
KNOWLEDGE_BASE_DIR = "knowledge_base"
KNOWLEDGE_BASE_MAX_ACTIONS = 15
