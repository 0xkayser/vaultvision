#!/usr/bin/env python3
"""Engagement engine: find and reply to relevant Hyperliquid/vault tweets."""

import sys
import os
import json
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from dotenv import load_dotenv
load_dotenv(os.path.join(os.path.dirname(os.path.dirname(__file__)), '.env'), override=True)

import tweepy
import anthropic

MY_ID = "952877063777718272"

# Accounts to monitor for reply opportunities
WATCH_ACCOUNTS = [
    "HyperliquidX",
    "SystemicStratHL",
    "GrowiHF",
    "DoCryptoBred",
]

# Search keywords
KEYWORDS = [
    "hyperliquid vault",
    "HLP vault",
    "vault strategy",
    "hyperliquid depositor",
]

DAILY_LIMITS = {"likes": 5, "replies": 3, "retweets": 2}
DAILY_FILE = "/tmp/vv_engage_daily.json"

REPLY_STYLE = """You are @0xkayser, founder of VaultVision. Generate a helpful reply to this tweet.

Rules:
- Be genuinely helpful, not promotional
- If relevant, mention a specific data point or insight about vaults
- Only mention vaultvision.tech if it DIRECTLY helps answer their question
- Keep it short (1-2 sentences, max 200 chars)
- Builder voice: knowledgeable, direct, no fluff
- NO emojis, NO hashtags
- If the tweet isn't relevant to vaults/analytics, return SKIP
"""


def get_client():
    return tweepy.Client(
        consumer_key=os.getenv('TWITTER_API_KEY'),
        consumer_secret=os.getenv('TWITTER_API_SECRET'),
        access_token=os.getenv('TWITTER_ACCESS_TOKEN'),
        access_token_secret=os.getenv('TWITTER_ACCESS_SECRET'),
        bearer_token=os.getenv('TWITTER_BEARER'),
    )


def load_daily():
    try:
        with open(DAILY_FILE) as f:
            d = json.load(f)
        if d.get("date") != time.strftime("%Y-%m-%d"):
            return {"date": time.strftime("%Y-%m-%d"), "likes": 0, "replies": 0, "retweets": 0, "seen": []}
        return d
    except Exception:
        return {"date": time.strftime("%Y-%m-%d"), "likes": 0, "replies": 0, "retweets": 0, "seen": []}


def save_daily(d):
    with open(DAILY_FILE, "w") as f:
        json.dump(d, f)


def generate_reply(tweet_text):
    """Generate a contextual reply using Claude."""
    client = anthropic.Anthropic(api_key=os.getenv('ANTHROPIC_API_KEY'))
    message = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=200,
        system=REPLY_STYLE,
        messages=[{"role": "user", "content": f"Tweet to reply to:\n\n{tweet_text}"}]
    )
    reply = message.content[0].text.strip()
    if "SKIP" in reply:
        return None
    if reply.startswith('"') and reply.endswith('"'):
        reply = reply[1:-1]
    return reply


def search_and_engage():
    """Search for relevant tweets and engage."""
    client = get_client()
    daily = load_daily()

    print(f"Daily stats: {daily['likes']} likes, {daily['replies']} replies, {daily['retweets']} RTs")

    # Search for vault-related tweets
    for keyword in KEYWORDS:
        if daily["replies"] >= DAILY_LIMITS["replies"] and daily["likes"] >= DAILY_LIMITS["likes"]:
            print("Daily limits reached")
            break

        try:
            tweets = client.search_recent_tweets(
                query=f"{keyword} -is:retweet -from:0xkayser lang:en",
                max_results=10,
                tweet_fields=["created_at", "public_metrics", "author_id"],
            )
        except Exception as e:
            print(f"Search error for '{keyword}': {e}")
            continue

        if not tweets.data:
            continue

        for tweet in tweets.data:
            if str(tweet.id) in daily["seen"]:
                continue

            metrics = tweet.public_metrics
            print(f"\n--- Tweet {tweet.id} ({metrics['like_count']} likes)")
            print(f"    {tweet.text[:100]}...")

            # Like tweets with engagement
            if metrics["like_count"] >= 3 and daily["likes"] < DAILY_LIMITS["likes"]:
                try:
                    client.like(MY_ID, tweet.id)
                    daily["likes"] += 1
                    print(f"    LIKED ({daily['likes']}/{DAILY_LIMITS['likes']})")
                except Exception as e:
                    print(f"    Like error: {e}")

            # Reply to good tweets
            if metrics["like_count"] >= 5 and daily["replies"] < DAILY_LIMITS["replies"]:
                reply = generate_reply(tweet.text)
                if reply:
                    print(f"    Reply: {reply}")
                    confirm = input("    Post reply? (y/n): ").strip().lower()
                    if confirm == "y":
                        try:
                            client.create_tweet(text=reply, in_reply_to_tweet_id=tweet.id)
                            daily["replies"] += 1
                            print(f"    REPLIED ({daily['replies']}/{DAILY_LIMITS['replies']})")
                        except Exception as e:
                            print(f"    Reply error: {e}")
                else:
                    print("    SKIP (not relevant)")

            daily["seen"].append(str(tweet.id))
            save_daily(daily)
            time.sleep(1)

    print(f"\nFinal: {daily['likes']} likes, {daily['replies']} replies")
    save_daily(daily)


def monitor_mentions():
    """Check for mentions and notify."""
    client = get_client()
    mentions = client.get_users_mentions(MY_ID, max_results=5, tweet_fields=["created_at", "text"])
    if mentions.data:
        print("Recent mentions:")
        for m in mentions.data:
            print(f"  {m.created_at}: {m.text[:100]}...")


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "engage"

    if cmd == "engage":
        search_and_engage()
    elif cmd == "mentions":
        monitor_mentions()
    elif cmd == "reply":
        # Manual reply: python engage.py reply TWEET_ID
        tweet_id = sys.argv[2]
        client = get_client()
        tweet = client.get_tweet(tweet_id, tweet_fields=["text"])
        if tweet.data:
            print(f"Tweet: {tweet.data.text}")
            reply = generate_reply(tweet.data.text)
            if reply:
                print(f"Reply: {reply}")
                confirm = input("Post? (y/n): ").strip().lower()
                if confirm == "y":
                    client.create_tweet(text=reply, in_reply_to_tweet_id=tweet_id)
                    print("Posted!")
    else:
        print("Usage: python engage.py [engage|mentions|reply TWEET_ID]")
