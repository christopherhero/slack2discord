# Slack to Discord Importer

This tool enables you to import messages from a specific Slack channel and post them to a designated Discord channel. The importer supports messages, threads, files (images, documents), and emojis, ensuring a seamless migration. Note: The script imports messages from the last 24 hours relative to the time it is executed. To avoid duplicate imports, it is recommended to schedule the script to run once per day (e.g., using `crontab`). Parameterizing this behavior is a potential enhancement.

---

## Features

- Import Slack messages to Discord, including threads.
- Transfer files (images, documents, etc.).
- Preserve emojis in messages.
- Imports messages from the last 24 hours relative to execution time.

### To-Do:
- Add support for importing reactions.
- Parameterize the time range for imports (e.g., set specific hours or custom durations).

---

## Requirements

- Python 3.8+
- `discord.py==2.0.0`
- `slack-sdk==3.19.6`
- `requests==2.28.1`
- `python-dotenv==0.21.0`

---

## Installation

1. Clone this repository:
   ```bash
   git clone https://github.com/yourusername/slack-to-discord-importer.git
   cd slack-to-discord-importer
   ```

2. Install the required dependencies:
   ```bash
   pip3 install -r requirements.txt
   ```

3. Create a `.env` file with the following environment variables:
   ```env
   SLACK_API_TOKEN=slack_token
   SLACK_CHANNEL_ID="slack channel id in string"

   DISCORD_BOT_TOKEN=discord_bot_token
   DISCORD_CHANNEL_ID=discord_channel_id_in_integer
   ```

4. Run the script:
   ```bash
   python3 script_name.py
   ```

---

### Bot Permissions

### Slack Bot Permissions
To function correctly, the Slack bot requires the following OAuth scopes:

| **OAuth Scope**         | **Description**                                                                 |
|-------------------------|-------------------------------------------------------------------------------|
| `channels:history`      | View messages and other content in public channels that slack2discord has been added to |
| `channels:read`         | View basic information about public channels in a workspace                     |
| `files:read`            | View files shared in channels and conversations that slack2discord has been added to |
| `groups:read`           | View basic information about private channels that slack2discord has been added to |
| `metadata.message:read` | Allows slack2discord to read message metadata in channels that slack2discord has been added to |
| `users:read`            | View people in a workspace                                                    |
| `users.profile:read`    | View profile details about people in a workspace                              |

### Discord Bot Permissions
The Discord bot must have these permissions for the designated channel:
- `View Channel`
- `Send Messages`
- `Attach Files`
- `Manage Threads`
- `Create Public Threads`
- `Send Messages in Threads`

### Adding Bots and Fetching Channel IDs
Before running the script, ensure the following steps are completed:
1. Add the Slack bot to your Slack workspace and the desired channel.
2. Add the Discord bot to your Discord server with the required permissions.
3. Obtain the Slack channel ID by navigating to the desired channel in Slack, clicking the channel name, and copying the `Channel ID` from the settings or URL.
4. Obtain the Discord channel ID by enabling Developer Mode in Discord settings, right-clicking the desired channel, and selecting "Copy ID."

---

## Usage
1. Ensure the bot is added to both Slack and Discord with the necessary permissions.
2. Modify the `.env` file to specify the Slack channel and Discord channel to be synced.
3. Schedule the script to run once per day to avoid duplicate imports. For example, using `crontab`:
   ```bash
   0 0 * * * /usr/bin/python3 /path/to/script.py
   ```
---

## Logs
The script generates a `debug.log` file to help monitor activities and debug any issues.

---
