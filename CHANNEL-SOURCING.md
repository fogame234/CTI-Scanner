# Getting started: channel sourcing

> The `/scan`, `/resolve`, and `/monitor` commands referenced below are from the optional companion bot (see COMPANION-BOT.md). All of these actions can also be done from the web UI under **Settings > Channels**.

## Search terms that produce quality results

Don't search for single words. These compound queries return channels
where threat actors actually operate, not news aggregators or scam groups.

### Stealer logs and infostealers
```
/scan redline logs
/scan raccoon stealer
/scan vidar logs
/scan lumma stealer
/scan stealer logs free
/scan cloud logs
/scan meta stealer
/scan aurora stealer
```

### Initial access and credentials
```
/scan initial access broker
/scan RDP access shop
/scan corporate access
/scan VPN access sale
/scan combolist fresh
/scan credential stuffing
/scan brute results
```

### Ransomware
```
/scan lockbit affiliate
/scan ransomware leak
/scan ransom proof
/scan data extortion
```

### Carding and financial fraud
```
/scan fullz CVV
/scan carding method
/scan dumps track2
/scan bank logs
```

### Exploit and vulnerability
```
/scan exploit POC
/scan 0day sale
/scan vulnerability research
/scan bug bounty leak
```

### General threat intel (legitimate researcher channels)
```
/scan threat intelligence feed
/scan malware analysis
/scan APT research
/scan IOC feed
/scan darknet monitoring
```

## How to evaluate a channel before monitoring

After `/scan` returns results, don't blindly `/monitor` everything.
For each channel, run `/resolve` and check:

1. **Member count** — under 500 members is often dead or a honeypot.
   Over 50,000 is usually a news aggregator, not a primary source.
   Sweet spot for active threat actor channels is 1,000–30,000.

2. **Description / about** — legitimate threat actor channels usually
   state what they sell or share. Researcher channels describe their
   focus area. Vague descriptions ("best channel") are a red flag.

3. **Post frequency** — join manually first and scroll through recent
   posts. A channel that posts 200 messages a day is either very
   active (good) or full of spam/off-topic chat (bad). A channel
   with 3 posts in the last month isn't worth monitoring.

4. **Language** — Russian and English channels tend to have the most
   actionable content. Channels that are purely in languages you
   can't triage will generate noise you can't evaluate.

5. **Content type** — is the channel posting actual IOCs, tools,
   samples, and credentials? Or is it reposting news articles?
   Primary sources are more valuable than aggregators.

## Recommended starting set

Start with 3-5 channels maximum. Run for a week. Review the IOC
extraction quality and alert noise. Then add more.

**Phase 1: validation (week 1)**
Pick 2 known threat intel researcher channels and 1 known threat
actor channel. This lets you validate that extraction works correctly
on content you can verify.

**Phase 2: expand (week 2-3)**
Add stealer log channels and initial access broker channels. These
produce the most actionable IOCs — IPs, domains, hashes, and wallet
addresses that directly map to active infrastructure.

**Phase 3: broaden (month 2+)**
Add ransomware leak channels, carding channels, and exploit channels.
By this point you'll have a feel for your alert keyword tuning and
can handle the increased volume.

## Alert keywords by category

### Starter set (low noise, high signal)
```
stealer log
redline
raccoon stealer
lumma
vidar
initial access
RDP access
CVE-
0day
zero-day
proof of concept
```

### Add after tuning (medium noise)
```
combolist
credential dump
database leak
ransomware
data extortion
cobalt strike
brute force
```

### Only if needed (high noise, requires channel curation)
```
exploit
malware
phishing
botnet
```

## Channels to avoid

- **"Free" everything channels** — "Free Netflix accounts", "Free
  PayPal logs" — these are almost entirely scams posting fake content
  to build subscriber counts.

- **Cryptocurrency pump/dump groups** — they mention "exploit" and
  "access" constantly but in a financial context. Your IOC extractor
  will pull hundreds of irrelevant wallet addresses.

- **News repost bots** — channels that just forward articles from
  BleepingComputer, The Record, etc. You can read those directly.

- **Channels with "VIP" upsells** — channels where every post ends
  with "join VIP for real content" are bait channels. The free tier
  has nothing useful.
