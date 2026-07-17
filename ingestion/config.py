# pip install aiohttp feedparser pydantic
#
# Paste your RSS/Atom feed URLs below (one per line).

RSS_FEED_LINKS = [
    # ----------------------------------------------------------------
    # Legacy research blogs (original set)
    # ----------------------------------------------------------------
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

    # ----------------------------------------------------------------
    # Tier-1 major cybersecurity news outlets
    # ----------------------------------------------------------------
    "https://feeds.feedburner.com/TheHackersNews",       # The Hacker News
    "https://www.darkreading.com/rss.xml",               # Dark Reading
    "https://cybersecuritynews.com/feed/",               # Cyber Security News
    "https://www.bleepingcomputer.com/feed/",            # BleepingComputer
    "https://krebsonsecurity.com/feed/",                 # Krebs on Security
    "https://www.wired.com/feed/category/security/latest/rss",  # Wired Security
    "https://api.theregister.com/api/v1/article?query=tag:security&orderBy=published&site_id=2&remapper=rss&limit=25",  # The Register
    "https://www.securityweek.com/feed/",                # SecurityWeek
    "https://therecord.media/feed",                      # The Record (Recorded Future)
    "https://securityboulevard.com/feed/",               # Security Boulevard
    "https://hackread.com/feed/",                        # Hackread
    "https://thecyberexpress.com/feed/",                 # The Cyber Express
    "https://www.theguardian.com/technology/data-computer-security/rss",  # Guardian Security

    # ----------------------------------------------------------------
    # Government, CERTs & national advisories
    # ----------------------------------------------------------------
    "https://www.cisa.gov/news.xml",                     # CISA News
    "https://www.cisa.gov/blog.xml",                     # CISA Blog
    "https://www.cisa.gov/cybersecurity-advisories/all.xml",  # CISA Advisories
    "https://www.ncsc.gov.uk/api/1/services/v1/all-rss-feed.xml",        # NCSC All
    "https://www.ncsc.gov.uk/api/1/services/v1/guidance-rss-feed.xml",   # NCSC Guidance
    "https://www.ncsc.gov.uk/api/1/services/v1/news-rss-feed.xml",       # NCSC News
    "https://www.ncsc.gov.uk/api/1/services/v1/blog-post-rss-feed.xml",  # NCSC Blog
    "https://cert.europa.eu/publications/security-advisories-rss",       # CERT-EU Advisories
    "https://cert.europa.eu/publications/threat-intelligence-rss",       # CERT-EU Threat Intel
    "https://www.cisecurity.org/feed/advisories",        # MS-ISAC / CIS Advisories
    "https://www.cisecurity.org/feed/blog",              # CIS Blog
    "http://nextgov.com/rss/cybersecurity/",             # Nextgov/FCW Cybersecurity

    # ----------------------------------------------------------------
    # Threat intelligence platforms & research
    # ----------------------------------------------------------------
    "https://unit42.paloaltonetworks.com/category/threat-research/feed/",  # Unit 42 Research
    "https://unit42.paloaltonetworks.com/feed/",         # Unit 42 All
    "https://securelist.com/feed/",                      # Kaspersky Securelist
    "https://cyble.com/blog/feed/",                      # Cyble
    "https://feeds.feedburner.com/threatintelligence/pvexyqv7v0v",  # Threat Intelligence
    "https://threatcluster.io/feed.xml",                 # ThreatCluster
    "https://threatmon.io/feed/",                        # ThreatMon
    "https://www.greynoise.io/blog/rss.xml",             # GreyNoise
    "https://blog.pulsedive.com/rss/",                   # Pulsedive
    "https://www.cyber.gov.au/about-us/view-all-content/alerts-and-advisories/feed",  # ACSC
    "https://bfore.ai/feed/",                            # BforeAI
    "https://brandefense.io/feed/",                      # Brandefense
    "https://www.spamhaus.org/rss.xml",                  # Spamhaus
    "https://vuldb.com/rss/recent",                      # VulDB
    "https://www.exploit-db.com/rss.xml",                # Exploit-DB
    "https://opensourcemalware.com/rss.xml",             # OpenSourceMalware
    "https://ctrlaltintel.com/feed",                     # Ctrl-Alt-Intel
    "https://blog.predictivedefense.io/feed",            # Predictive Defense

    # ----------------------------------------------------------------
    # Cloud security
    # ----------------------------------------------------------------
    "https://cloudsecurityalliance.org/feed/",           # Cloud Security Alliance
    "https://www.cloudvulndb.org/rss/feed.xml",          # Open Cloud Vulnerability DB
    "https://cloudseclist.com/feed.xml",                 # CloudSecList
    "https://aws.amazon.com/blogs/security/feed/",       # AWS Security Blog
    "https://cloudblog.withgoogle.com/rss/",             # Google Cloud Blog
    "https://www.wiz.io/feed/rss.xml",                   # Wiz Blog
    "https://www.wiz.io/api/feed/cloud-threat-landscape/rss.xml",  # Wiz Cloud Threat Landscape
    "https://securitylabs.datadoghq.com/rss/feed.xml",  # Datadog Security Labs
    "https://www.sysdig.com/blog/rss.xml",               # Sysdig

    # ----------------------------------------------------------------
    # Vendor security research blogs
    # ----------------------------------------------------------------
    "https://www.microsoft.com/en-us/security/blog/feed/",   # Microsoft Security
    "https://www.crowdstrike.com/en-us/blog/feed",            # CrowdStrike
    "https://www.sentinelone.com/blog/feed/",                 # SentinelOne
    "https://www.huntress.com/blog/rss.xml",                  # Huntress
    "https://redcanary.com/feed/",                            # Red Canary
    "https://www.rapid7.com/rss.xml",                         # Rapid7
    "https://blog.cloudflare.com/rss/",                       # Cloudflare Blog
    "https://www.blackhillsinfosec.com/feed/",                # Black Hills InfoSec
    "http://trustedsec.com/feed.rss",                         # TrustedSec
    "http://elastic.co/security-labs/rss/feed.xml",           # Elastic Security Labs
    "https://www.reversinglabs.com/blog/rss.xml",             # ReversingLabs
    "https://asec.ahnlab.com/en/feed/",                       # AhnLab ASEC
    "https://www.vectra.ai/blog/rss.xml",                     # Vectra AI
    "https://www.morphisec.com/feed/?post_type=blog",         # Morphisec
    "https://socprime.com/blog/feed/",                        # SOC Prime
    "https://outpost24.com/blog/feed/",                       # Outpost24
    "https://www.infoblox.com/blog/feed/",                    # Infoblox
    "https://heimdalsecurity.com/blog/posts/feed/",           # Heimdal Security
    "https://www.jumpsec.com/feed/",                          # JUMPSEC
    "https://teamt5.org/en/posts/rss.xml",                    # TeamT5
    "https://www.virusbulletin.com/rss",                      # Virus Bulletin
    "https://blog.virustotal.com/feeds/posts/default",        # VirusTotal Blog
    "https://www.levelblue.com/blogs/levelblue-blog/rss.xml", # LevelBlue (AT&T)
    "https://www.pentestpartners.com/feed/",                  # Pen Test Partners
    "https://www.runzero.com/blog/index.xml",                 # runZero
    "https://www.threatlocker.com/blog/rss.xml",              # ThreatLocker
    "https://www.watchguard.com/wgrd-security-hub/secplicity-blog/feed",  # WatchGuard Secplicity

    # ----------------------------------------------------------------
    # Identity, IAM & cloud access security
    # ----------------------------------------------------------------
    "https://saviynt.com/blog/rss.xml",                  # Saviynt
    "https://www.idsalliance.org/blog/feed/",            # Identity Defined Security Alliance
    "https://www.silverfort.com/blog/feed/",             # Silverfort
    "https://www.cyera.com/blog/rss.xml",                # Cyera

    # ----------------------------------------------------------------
    # Detection engineering & blue team
    # ----------------------------------------------------------------
    "https://www.detectionengineering.net/feed",         # Detection Engineering Weekly
    "https://detect.fyi/feed",                           # Detect FYI
    "https://newtonpaul.com/rss.xml",                    # On the Hunt
    "https://rss.beehiiv.com/feeds/xgTKUmMmUm.xml",     # tl;dr sec
    "https://defend.network/feed.xml",                   # defend.network Daily Briefings

    # ----------------------------------------------------------------
    # Vulnerability research & exploit development
    # ----------------------------------------------------------------
    "https://blog.doyensec.com/atom.xml",                # Doyensec
    "https://blog.trailofbits.com/index.xml",            # Trail of Bits Blog
    "https://exploitreversing.com/feed/",                # Exploit Reversing
    "https://dayzerosec.com/feed.xml",                   # DAY[0]
    "https://projectzero.google/feed.xml",               # Google Project Zero
    "https://bartblaze.blogspot.com/feeds/posts/default",# Blaze's Security Blog
    "https://doublepulsar.com/feed",                     # DoublePulsar
    "https://kmsec.uk/rss.xml",                          # kmsec
    "https://recyclebin.zip/posts/index.xml",            # Recyclebin.zip
    "https://sensepost.com/blog/rss.xml",                # Orange Cyberdefense / SensePost
    "https://sensepost.com/rss.xml",                     # SensePost RSS
    "https://www.hackthebox.com/rss/blog/all",           # HackTheBox Blog
    "https://github.blog/tag/github-security-lab/feed/", # GitHub Security Lab
    "https://github.blog/enterprise-software/devsecops/feed/",  # GitHub DevSecOps

    # ----------------------------------------------------------------
    # Malware, forensics & incident response
    # ----------------------------------------------------------------
    "https://databreaches.net/feed/",                    # DataBreaches.Net
    "https://www.cybercrimediaries.com/blog-feed.xml",   # Cybercrime Diaries
    "https://www.forensicfocus.com/feed/",               # Forensic Focus
    "https://www.binalyze.com/blog/rss.xml",             # Binalyze (DFIR)

    # ----------------------------------------------------------------
    # AI & ML security
    # ----------------------------------------------------------------
    "https://www.ai-security-blog.com/rss.xml",          # AI Security Blog
    "https://protectai.com/blog/rss.xml",                # Protect AI
    "https://genai.owasp.org/blog/feed/",                # OWASP GenAI Security

    # ----------------------------------------------------------------
    # DevSecOps & developer security
    # ----------------------------------------------------------------
    "https://devops.com/category/blogs/feed/",           # DevOps.com
    "https://devsec-blog.com/feed/",                     # DevSec Blog
    "https://www.harness.io/blog/rss.xml",               # Harness
    "https://devsecopsai.today/feed",                    # DevSecOps & AI
    "https://www.aikido.dev/blog/rss.xml",               # Aikido Security
    "https://slack.engineering/feed/",                   # Slack Engineering

    # ----------------------------------------------------------------
    # Community, write-ups & research aggregators
    # ----------------------------------------------------------------
    "https://infosecwriteups.com/feed",                  # InfoSec Write-ups (Medium)
    "https://www.reddit.com/r/netsec/.rss",              # Reddit r/netsec
    "https://www.reddit.com/r/cybersecurity/.rss",       # Reddit r/cybersecurity
    "https://cybersecuritywriteups.com/feed",            # Cybersecurity Write-ups
    "https://softwareanalyst.substack.com/feed",         # Software Analyst Cyber Research
    "https://medium.com/@raghavtiresearch/feed",         # BeGoodToAll / Raghav Tires
    "http://medium.com/@TalBeerySec/feed",               # Tal Be'ery
    "https://itnext.io/feed",                            # ITNEXT
    "https://brainoverflow.blog/index.xml",              # brain overflow
    "https://blog.ammaraskar.com/feed",                  # Ammar's Blog

    # ----------------------------------------------------------------
    # Broader tech news (signal for cloud/platform incidents)
    # ----------------------------------------------------------------
    "https://www.forbes.com/innovation/feed2",           # Forbes Innovation
    "https://www.reddit.com/r/technology/.rss",          # Reddit r/technology
    "https://techcrunch.com/feed/",                      # TechCrunch
    "https://feeds.feedburner.com/govtech/blogs/lohrmann_on_infrastructure",  # Lohrmann on Cybersecurity
    "https://feeds.feedburner.com/GoogleAppsUpdates",    # Google Workspace Updates
    "https://www.cio.com/security/feed/",                # CIO Security
    "https://generativeai.pub/feed",                     # Generative AI
    "https://cloudsek.com/blog/rss.xml",                 # CloudSEK
    "https://www.cm-alliance.com/cybersecurity-blog/rss.xml",  # CM Alliance
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
# Only ingest feed items published within this many days (rolling window from UTC now)
INGESTION_MAX_AGE_DAYS = 7

# Local LLM — Ollama OpenAI-compatible API
OLLAMA_BASE_URL = "http://localhost:11434/v1"

# Step 2 — Gemma 4 verifier
OLLAMA_MODEL = "gemma4:e4b"
OLLAMA_TIMEOUT_SECONDS = 120
OLLAMA_MAX_WORKERS = 4

# Step 3 — phi4-mini-reasoning rule generation (local Ollama + LiteLLM alias)
OLLAMA_PHI4_MODEL = "phi4-mini-reasoning"
LITELLM_REASONING_MODEL = "ollama/phi4-mini-reasoning"
OLLAMA_PHI4_TIMEOUT_SECONDS = 300
OLLAMA_PHI4_MAX_WORKERS = 2
RULE_VARIANTS_MIN = 3
RULE_VARIANTS_MAX = 3

# Step 3 — grounded retrieval knowledge base
KNOWLEDGE_BASE_DIR = "knowledge_base"
KNOWLEDGE_BASE_MAX_ACTIONS = 15

# ---------------------------------------------------------------------------
# Step 2 — Tiered Semantic Deduplication
# ---------------------------------------------------------------------------

# LanceDB local vector store (persistent across pipeline runs)
LANCEDB_PATH = "data/lancedb_vectors"
LANCEDB_TABLE_NAME = "threat_vectors"

# Embedding model — sentence-transformers all-MiniLM-L6-v2
# Small (80 MB), 384-dimensional, CPU-friendly.
# Cache location: ~/.cache/torch/sentence_transformers/
EMBEDDING_MODEL_NAME = "all-MiniLM-L6-v2"
EMBEDDING_DIM = 384

# Tier 2: cosine distance ceiling.
# LanceDB returns cosine distance in [0, 1]; 0 = identical, 1 = orthogonal.
# 0.15 ≈ 0.85 cosine similarity — flags topics already covered in the pipeline.
COSINE_DISTANCE_THRESHOLD: float = 0.15

# Tier 1: SimHash Hamming distance ceiling.
# Hamming distance ≤ 3 over a 64-bit fingerprint flags near-textual duplicates.
SIMHASH_HAMMING_THRESHOLD: int = 3

# Rolling prune ceiling — maximum records kept in both the LanceDB table and
# the SimHash state file. Oldest entries are evicted when exceeded.
VECTOR_MAX_RECORDS: int = 500

# Persisted SimHash fingerprint state (survives across runs)
SIMHASH_STATE_PATH = "data/filter_simhash_state.json"
