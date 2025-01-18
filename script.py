from dotenv import load_dotenv
import os
import re
import slack_sdk
import discord
import requests
from datetime import datetime, timezone
from discord.ext import tasks
import io
import logging

# Logger settings
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("debug.log"),
        logging.StreamHandler()
    ]
)

load_dotenv('.env.local')
load_dotenv()

SLACK_TOKEN = os.getenv("SLACK_API_TOKEN")
SLACK_CHANNEL_ID = os.getenv("SLACK_CHANNEL_ID")

DISCORD_TOKEN = os.getenv("DISCORD_BOT_TOKEN")
DISCORD_CHANNEL_ID = int(os.getenv("DISCORD_CHANNEL_ID", 0))

# settings for  Discord
intents = discord.Intents.default()
intents.message_content = True
client = discord.Client(intents=intents)

# settings for Slack
slack_client = slack_sdk.WebClient(token=SLACK_TOKEN)
user_cache = {}

def get_user_info(user_id):
    """Get user information from the cache or Slack API."""
    if user_id not in user_cache:
        try:
            response = slack_client.users_info(user=user_id)
            if response['ok']:
                user = response['user']
                user_cache[user_id] = {
                    'name': user.get('real_name', 'Unknown'),
                    'avatar': user.get('profile', {}).get('image_192', '')
                }
                logging.info(f"User data fetched: {user_cache[user_id]}")
            else:
                user_cache[user_id] = {'name': 'Unknown', 'avatar': ''}
                logging.warning(f"An exception while fetching user info: {user_id}")
        except Exception as e:
            logging.error(f"An exception while fetching user info: {user_id}: {e}")
            user_cache[user_id] = {'name': 'Unknown', 'avatar': ''}
    return user_cache[user_id]

def fetch_message_files(message):
    """Download files associated with the message."""
    files = []
    if 'files' in message:
        for file in message['files']:
            file_url = file.get('url_private')
            if file_url:
                try:
                    headers = {'Authorization': f'Bearer {SLACK_TOKEN}'}
                    response = requests.get(file_url, headers=headers)
                    if response.status_code == 200:
                        if file['mimetype'].startswith('image/'):
                            files.append({
                                'type': 'image',
                                'content': response.content,
                                'filename': file.get('name', 'image.jpg')
                            })
                        else:
                            files.append({
                                'type': 'file',
                                'url': file_url,
                                'filename': file.get('name', 'file')
                            })
                    logging.info(f"FIle downloaded: {file['name']}")
                except Exception as e:
                    logging.error(f"An exception on downloading file {file_url}: {e}")
    return files

def fetch_thread_replies(channel_id, thread_ts):
    """Get the replies in the thread for the message given."""
    try:
        response = slack_client.conversations_replies(
            channel=channel_id,
            ts=thread_ts
        )
        replies = response.get("messages", [])

        logging.info(f"Downloaded {len(replies)} replies in thread for ts={thread_ts}.")
        return replies
    except Exception as e:
        logging.error(f"An exception while fetching response from thread {thread_ts}: {e}")
        return []


async def send_message_with_files(channel, message_text, files, parent_message=None):
    """
    Send a message with attachments on Discord, with advanced thread handling.
    Prevents adding main messages to threads.
    """
    if not message_text:
        return None

    # Prepare image files
    image_files = [
        discord.File(io.BytesIO(f['content']), filename=f['filename'])
        for f in files if f['type'] == 'image'
    ]

    try:
        # If there's a parent message, create a thread for replies
        if parent_message:
            # Ensure thread exists
            if not parent_message.thread:
                thread = await parent_message.create_thread(name="Slack Thread")
            else:
                thread = parent_message.thread

            # Send reply in the thread
            sent_message = await thread.send(
                content=message_text,
                files=image_files or None
            )
            logging.info(f"Message sent in thread: {message_text[:50]}")

        # Send as a regular message if no parent message
        else:
            sent_message = await channel.send(
                content=message_text,
                files=image_files or None
            )
            logging.info(f"Main message sent: {message_text[:50]}")

        # Handle additional files (non-image)
        for file in [f for f in files if f['type'] == 'file']:
            if parent_message and parent_message.thread:
                await parent_message.thread.send(f"File: {file['url']}")
            else:
                await channel.send(f"File: {file['url']}")

            logging.info(f"Send File: {file['url']}")

        return sent_message

    except Exception as e:
        logging.error(f"Exception while sending message: {e}")
        return None

def extract_message_content(message):
    # Extracting the message content
    try:
        if 'text' in message and message['text']:
            return message['text']

        if 'blocks' in message and message['blocks']:
            return process_slack_blocks(message['blocks'])

        return "[NO MESSAGE]"
    except Exception as e:
        print(f"An exception while message parsing: {e}")
        return "Failed to process message"

def format_messages(messages):
    """It formats messages from the Slack channel, taking into account threads."""
    formatted_messages = {}  # Map for main message storage

    for message in messages:
        if not message or not isinstance(message, dict):
            continue

        # Logging messages for debugging
        logging.info(f"Processing message: {message.get('ts', 'no ts')}, user: {message.get('user', 'no user')}")

        # Get user data and format message
        user_info = get_user_info(message.get('user', ''))
        timestamp = float(message.get('ts', 0))
        date_time = datetime.fromtimestamp(timestamp, tz=timezone.utc)

        # Extract message content
        message_content = extract_message_content(message)
        message_files = fetch_message_files(message)

        formatted_message = (
            f"**{user_info['name']}** - {date_time.strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"{message_content}"
        )

        if 'thread_ts' in message:  # The message is part of a thread
            parent_ts = message['thread_ts']

            # Get replies in the thread if this is the first message
            if parent_ts not in formatted_messages:
                # Find the original message (not a reply)
                original_message = next(
                    (msg for msg in messages if msg.get('ts') == parent_ts),
                    None
                )

                if original_message:
                    orig_user_info = get_user_info(original_message.get('user', ''))
                    orig_timestamp = float(original_message.get('ts', 0))
                    orig_date_time = datetime.fromtimestamp(orig_timestamp, tz=timezone.utc)
                    orig_content = extract_message_content(original_message)
                    orig_files = fetch_message_files(original_message)

                    formatted_original = (
                        f"**{orig_user_info['name']}** - {orig_date_time.strftime('%Y-%m-%d %H:%M:%S')}\n"
                        f"{orig_content}"
                    )

                    formatted_messages[parent_ts] = {
                        'text': formatted_original,
                        'files': orig_files,
                        'replies': []
                    }

                replies = fetch_thread_replies(SLACK_CHANNEL_ID, parent_ts)
                for reply in replies:
                    # Skip the original message when processing replies
                    if reply.get('ts') == parent_ts:
                        continue

                    reply_content = extract_message_content(reply)
                    reply_files = fetch_message_files(reply)
                    reply_user_info = get_user_info(reply.get('user', ''))
                    reply_timestamp = float(reply.get('ts', 0))
                    reply_date_time = datetime.fromtimestamp(reply_timestamp, tz=timezone.utc)
                    reply_formatted = (
                        f"**{reply_user_info['name']}** - {reply_date_time.strftime('%Y-%m-%d %H:%M:%S')}\n"
                        f"{reply_content}"
                    )
                    formatted_messages[parent_ts]['replies'].append({
                        'text': reply_formatted,
                        'files': reply_files
                    })
        else:  # Main message
            ts = message.get('ts')
            formatted_messages[ts] = {
                'text': formatted_message,
                'files': message_files,
                'replies': []
            }

    return formatted_messages

@client.event
async def on_ready():
    """
    Main function to process and send Slack messages to Discord.
    Handles messages with and without threads.
    """
    print(f"Logged in discord as {client.user}")
    logging.info(f"Logged in discord as {client.user}")

    today = datetime.now(timezone.utc).date()

    try:
        # Fetch messages from Slack
        response = slack_client.conversations_history(
            channel=SLACK_CHANNEL_ID,
            oldest=datetime.combine(today, datetime.min.time()).timestamp(),
            latest=datetime.combine(today, datetime.max.time()).timestamp(),
            inclusive=True,
            limit=1000
        )

        messages = response.get("messages", [])
        logging.info(f"Downloaded {len(messages)} messages from Slack channel.")

        # Format messages
        formatted_messages = format_messages(messages)
        if not formatted_messages:
            logging.info("No formatted messages to send.")
            return

        # Get Discord channel
        discord_channel = client.get_channel(DISCORD_CHANNEL_ID)
        sent_messages = {}  # Dictionary to store sent messages

        # Process messages sorted by timestamp
        for msg_ts, msg_data in sorted(formatted_messages.items(), key=lambda x: float(x[0])):
            # Prepare image files for main message
            image_files = [
                discord.File(io.BytesIO(f['content']), filename=f['filename'])
                for f in msg_data.get('files', []) if f['type'] == 'image'
            ]

            # Check if message has replies (thread)
            if 'replies' in msg_data and msg_data['replies']:
                # Send main message
                main_message = await discord_channel.send(
                    content=msg_data['text'],
                    files=image_files or None
                )
                sent_messages[msg_ts] = main_message

                # Create thread and send replies
                thread = await main_message.create_thread(name="Slack Thread")

                for reply in msg_data['replies']:
                    reply_image_files = [
                        discord.File(io.BytesIO(f['content']), filename=f['filename'])
                        for f in reply.get('files', []) if f['type'] == 'image'
                    ]
                    await thread.send(
                        content=reply['text'],
                        files=reply_image_files or None
                    )
            else:
                # Send regular message without thread
                await discord_channel.send(
                    content=msg_data['text'],
                    files=image_files or None
                )

        logging.info("Messages were sent on Discord.")

    except Exception as e:
        logging.error(f"Error while downloading or sending messages: {e}")
        import traceback
        traceback.print_exc()

    await client.close()

if __name__ == "__main__":
    client.run(DISCORD_TOKEN)
