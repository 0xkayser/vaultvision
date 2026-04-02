#!/usr/bin/env python3
"""Post a tweet or thread to @0xkayser via Twitter API v2."""

import sys
import os
import json
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from dotenv import load_dotenv
load_dotenv(os.path.join(os.path.dirname(os.path.dirname(__file__)), '.env'), override=True)

import tweepy


def get_client():
    return tweepy.Client(
        consumer_key=os.getenv('TWITTER_API_KEY'),
        consumer_secret=os.getenv('TWITTER_API_SECRET'),
        access_token=os.getenv('TWITTER_ACCESS_TOKEN'),
        access_token_secret=os.getenv('TWITTER_ACCESS_SECRET'),
    )


def post_tweet(text, reply_to=None):
    """Post a single tweet. Returns tweet ID."""
    client = get_client()
    kwargs = {"text": text}
    if reply_to:
        kwargs["in_reply_to_tweet_id"] = reply_to
    result = client.create_tweet(**kwargs)
    tweet_id = result.data["id"]
    print(f"Posted: {tweet_id}")
    print(f"https://x.com/0xkayser/status/{tweet_id}")
    return tweet_id


def post_thread(tweets):
    """Post a thread (list of strings). Returns list of tweet IDs."""
    ids = []
    reply_to = None
    for i, text in enumerate(tweets):
        tweet_id = post_tweet(text, reply_to=reply_to)
        ids.append(tweet_id)
        reply_to = tweet_id
        if i < len(tweets) - 1:
            time.sleep(2)
    print(f"\nThread posted: {len(ids)} tweets")
    return ids


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python tweet.py 'text'              # single tweet")
        print("  python tweet.py --thread file.json   # thread from JSON array")
        print("  python tweet.py --reply ID 'text'    # reply to tweet")
        sys.exit(1)

    if sys.argv[1] == "--thread":
        with open(sys.argv[2]) as f:
            tweets = json.load(f)
        post_thread(tweets)
    elif sys.argv[1] == "--reply":
        post_tweet(sys.argv[3], reply_to=sys.argv[2])
    else:
        post_tweet(sys.argv[1])
