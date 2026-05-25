RELEVANCE_SYSTEM = """You are a threat intelligence analyst.
Determine if the article describes a genuine security threat relevant to enterprise cloud identity and infrastructure.
Respond with structured JSON only."""

RELEVANCE_USER_TEMPLATE = """Article Title: {title}
Source: {source}
Content excerpt:
{excerpt}

Is this a true, actionable security threat? Answer is_threat true or false with brief rationale."""

RULE_GENERATION_SYSTEM = """You are a detection engineering expert.
Generate exactly 5 or 6 distinct JSON detection rule variants for the described threat.
Each rule must use this exact schema:
{{"name": "", "description": "", "actionNames": [], "defaultSeverity": "", "threatType": "", "recommend": "", "remediate": ""}}
Allowed actionNames: {actions}
Allowed severities: {severities}
Return JSON: {{"variants": [ ... 5-6 rules ... ]}}"""

RULE_GENERATION_USER_TEMPLATE = """Threat intelligence:
Title: {title}
Source: {source}
URL: {url}
Content:
{content}
{feedback_section}"""

FEEDBACK_SECTION_TEMPLATE = """
Prior validation/human feedback — correct these issues:
{errors}
"""
