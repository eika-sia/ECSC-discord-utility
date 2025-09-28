import os
import asyncio
import aiohttp
import discord
import json

# --- Setup pwntools Logger ---
from pwn import log

def log_info(message):
    log.info(message)

def log_success(message):
    log.success(message)

def log_error(message):
    log.error(message)

def log_warning(message):
    log.warning(message)


# --- Environment Variables ---
try:
    DISCORD_BOT_TOKEN = os.environ['DISCORD_BOT_TOKEN']
    DISCORD_CHANNEL_ID = int(os.environ['DISCORD_CHANNEL_ID'])
    API_HOST_PORT = os.environ['API_HOST_PORT'] # e.g., "10.42.251.2:8080"
    TICK_LENGTH_SECONDS = int(os.environ['TICK_LENGTH_SECONDS'])
    TEAM_ID = int(os.environ['TEAM_ID'])
    # Optional: Sensitivity for attack/defense drops. Adjust as needed.
    ATK_DEF_DROP_PERCENTAGE_THRESHOLD = float(os.environ.get('ATK_DEF_DROP_PERCENTAGE_THRESHOLD', 0.5))
    ATK_DEF_MIN_SCORE_THRESHOLD = float(os.environ.get('ATK_DEF_MIN_SCORE_THRESHOLD', 10.0)) # Only alert if score is above this to avoid noise from 0 scores
except KeyError as e:
    log_error(f"Missing required environment variable: {e}")
    exit(1)
except ValueError as e:
    log_error(f"Invalid value for environment variable: {e}")
    exit(1)

# --- Global State for Monitoring ---
# Stores the last known state of services for comparison
last_service_states = {} # {service_name: {"checker": "OK/FAULTY", "attack": float, "defense": float}}

# --- Discord Bot Setup ---
intents = discord.Intents.default()
intents.message_content = True # Required for monitoring channel activities if needed, though not strictly for this bot.
client = discord.Client(intents=intents)

async def send_discord_message(message_content: str):
    """Sends a message to the configured Discord channel."""
    await client.wait_until_ready()
    try:
        channel = client.get_channel(DISCORD_CHANNEL_ID)
        if channel:
            await channel.send(message_content)
            log_success(f"Sent Discord message to channel {DISCORD_CHANNEL_ID}: '{message_content}'")
        else:
            log_error(f"Discord channel with ID {DISCORD_CHANNEL_ID} not found.")
    except Exception as e:
        log_error(f"Failed to send Discord message: {e}")

async def fetch_score_data():
    """Fetches score data for the specified team from the API."""
    api_url = f"http://{API_HOST_PORT}/api/v1/score?team={TEAM_ID}"
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(api_url) as response:
                response.raise_for_status() # Raise an exception for bad status codes
                data = await response.json()
                log_success(f"Fetched score data from {api_url}")
                return data
    except aiohttp.ClientError as e:
        log_error(f"API Client Error fetching data from {api_url}: {e}")
        return None
    except json.JSONDecodeError as e:
        log_error(f"JSON Decode Error from API response: {e}")
        return None
    except Exception as e:
        log_error(f"An unexpected error occurred while fetching score data: {e}")
        return None

async def monitor_services():
    """Monitors service states and sends Discord alerts."""
    global last_service_states
    log_info("Starting service monitor loop...")

    # Track previous deltas for each service and last tick value
    prev_deltas = {}  # {service_name: {"attack_delta": float, "defense_delta": float}}
    last_tick = None

    while True:
        log_info(f"Fetching data for team {TEAM_ID}...")
        team_data = await fetch_score_data()
        if not team_data:
            log_warning("No data fetched or API error. Waiting for next tick.")
            await asyncio.sleep(TICK_LENGTH_SECONDS)
            continue
        CurrTick = list(team_data.keys())[0]
        current_team_services = team_data.get(CurrTick, {})
        if not current_team_services:
            log_warning(f"No services found for team {TEAM_ID} in the fetched data. Waiting for next tick.")
            await asyncio.sleep(TICK_LENGTH_SECONDS)
            continue
        current_service_states = {}

        faulty_services = []
        attack_issue_services = []
        defense_issue_services = []

        # Only trigger alerts and update deltas if tick changed
        if last_tick != CurrTick:
            log_info(f"Processing {len(current_team_services)} services...")
            # Take a snapshot of prev_deltas before updating
            prev_deltas_snapshot = {k: v.copy() for k, v in prev_deltas.items()}
            for service_name, service_info in current_team_services.items():
                current_checker_status = service_info.get("checker")
                current_attack_score = service_info.get("components", {}).get("attack", 0.0)
                current_defense_score = service_info.get("components", {}).get("defense", 0.0)
                prev_attack_score = last_service_states.get(service_name, {}).get("attack", None)
                prev_defense_score = last_service_states.get(service_name, {}).get("defense", None)
                attack_delta = current_attack_score - prev_attack_score if prev_attack_score is not None else None
                defense_delta = current_defense_score - prev_defense_score if prev_defense_score is not None else None

                # Use stored deltas for logging
                atk_delta_str = f"{attack_delta:+.2f}" if attack_delta is not None else "N/A"
                def_delta_str = f"{defense_delta:+.2f}" if defense_delta is not None else "N/A"
                log_info(f"Monitoring '{service_name}': Checker='{current_checker_status}', Atk = {current_attack_score:.2f} ({atk_delta_str}), Def = {current_defense_score:.2f} ({def_delta_str})")

                # --- Attack Delta Drop Alert (compare previous delta to current delta) ---
                prev_attack_delta = prev_deltas_snapshot.get(service_name, {}).get("attack_delta", None)
                if attack_delta is not None and prev_attack_delta is not None and prev_attack_delta != 0:
                    if attack_delta < prev_attack_delta:
                        drop_percentage = abs(attack_delta - prev_attack_delta) / abs(prev_attack_delta)
                        if drop_percentage >= ATK_DEF_DROP_PERCENTAGE_THRESHOLD and abs(prev_attack_delta) >= ATK_DEF_MIN_SCORE_THRESHOLD:
                            attack_issue_services.append(service_name)
                            log_warning(f"Service '{service_name}' attack delta dropped: {prev_attack_delta:.2f} -> {attack_delta:.2f} ({drop_percentage:.2%})")

                # --- Defense Delta Drop Alert (compare previous delta to current delta) ---
                prev_defense_delta = prev_deltas_snapshot.get(service_name, {}).get("defense_delta", None)
                if defense_delta is not None and prev_defense_delta is not None and prev_defense_delta != 0:
                    if defense_delta < prev_defense_delta:
                        drop_percentage = abs(defense_delta - prev_defense_delta) / abs(prev_defense_delta)
                        if drop_percentage >= ATK_DEF_DROP_PERCENTAGE_THRESHOLD and abs(prev_defense_delta) >= ATK_DEF_MIN_SCORE_THRESHOLD:
                            defense_issue_services.append(service_name)
                            log_warning(f"Service '{service_name}' defense delta dropped: {prev_defense_delta:.2f} -> {defense_delta:.2f} ({drop_percentage:.2%})")

                # Checker status alert (compare with last_service_states)
                if service_name in last_service_states:
                    prev_state = last_service_states[service_name]
                    prev_checker_status = prev_state.get("checker")
                    if (prev_checker_status == "SUCCESS" or prev_checker_status == "RECOVERING") and (current_checker_status == "OFFLINE" or current_checker_status == "MUMBLE"):
                        faulty_services.append(service_name)
                        log_warning(f"Service '{service_name}' changed from {prev_checker_status} to {current_checker_status}!")
                else:
                    log_info(f"Initialized state for new or previously unknown service: '{service_name}'")

                # Update prev_deltas for next tick
                prev_deltas[service_name] = {
                    "attack_delta": attack_delta,
                    "defense_delta": defense_delta
                }
            last_tick = CurrTick
        else:
            # For logging in repeated polls, use stored deltas
            for service_name, service_info in current_team_services.items():
                current_checker_status = service_info.get("checker")
                current_attack_score = service_info.get("components", {}).get("attack", 0.0)
                current_defense_score = service_info.get("components", {}).get("defense", 0.0)
                current_service_states[service_name] = {
                    "checker": current_checker_status,
                    "attack": current_attack_score,
                    "defense": current_defense_score
                }
                attack_delta = prev_deltas.get(service_name, {}).get("attack_delta", None)
                defense_delta = prev_deltas.get(service_name, {}).get("defense_delta", None)
                atk_delta_str = f"{attack_delta:+.2f}" if attack_delta is not None else "N/A"
                def_delta_str = f"{defense_delta:+.2f}" if defense_delta is not None else "N/A"
            log_info(f"Monitoring {len(current_team_services)} services...")


        # --- Send Discord Alerts ---
        # Service Down Alerts (OFFLINE/MUMBLE)
        if faulty_services:
            down_msgs = []
            for service_name in faulty_services:
                current_status = current_team_services[service_name].get("checker", "OFFLINE")
                status_term = "offline" if current_status == "OFFLINE" else "mumble"
                down_msgs.append(f"`{service_name}` is `{status_term}`")
            message = '\n'.join(down_msgs) + "\n@everyone"
            await send_discord_message(message)

        # Atk/Def Drops
        atk_msgs = []
        def_msgs = []
        # Use previous deltas snapshot for correct reporting
        for service_name in attack_issue_services:
            previous_delta = prev_deltas_snapshot.get(service_name, {}).get("attack_delta", None)
            prev_attack_score = last_service_states.get(service_name, {}).get("attack", None)
            current_attack_score = current_team_services[service_name].get("components", {}).get("attack", 0.0)
            current_delta = None
            if prev_attack_score is not None:
                current_delta = current_attack_score - prev_attack_score
            if previous_delta is not None and current_delta is not None:
                percent_change = 0
                if previous_delta != 0:
                    percent_change = ((current_delta - previous_delta) / abs(previous_delta)) * 100
                atk_msgs.append(f"`{service_name}` has `ATTACK` issue\n-# {abs(percent_change):.2f}% change ({previous_delta:+.2f}->{current_delta:+.2f})")
        for service_name in defense_issue_services:
            previous_delta = prev_deltas_snapshot.get(service_name, {}).get("defense_delta", None)
            prev_defense_score = last_service_states.get(service_name, {}).get("defense", None)
            current_defense_score = current_team_services[service_name].get("components", {}).get("defense", 0.0)
            current_delta = None
            if prev_defense_score is not None:
                current_delta = current_defense_score - prev_defense_score
            if previous_delta is not None and current_delta is not None:
                percent_change = 0
                if previous_delta != 0:
                    percent_change = ((current_delta - previous_delta) / abs(previous_delta)) * 100
                def_msgs.append(f"`{service_name}` has `DEFENSE` issue\n-# {abs(percent_change):.2f}% change ({previous_delta:+.2f}->{current_delta:+.2f})")
        if atk_msgs or def_msgs:
            message = '\n'.join(atk_msgs + def_msgs) + "\n@everyone"
            await send_discord_message(message)

        # Update last_service_states for the next iteration
        last_service_states = current_service_states
        if CurrTick != last_tick:
            log_success("Service states updated. Waiting for next tick.")
        await asyncio.sleep(TICK_LENGTH_SECONDS)

@client.event
async def on_ready():
    """Called when the bot is ready and connected to Discord."""
    log_success(f'Logged in as {client.user} (ID: {client.user.id})')
    log_info(f'Monitoring API at: http://{API_HOST_PORT}/api/v1/score?team={TEAM_ID}')
    log_info(f'Tick length: {TICK_LENGTH_SECONDS} seconds')
    log_info(f'Sending alerts to channel ID: {DISCORD_CHANNEL_ID}')
    log_info(f'Attack/Defense drop threshold: {ATK_DEF_DROP_PERCENTAGE_THRESHOLD*100:.0f}%')

    # Start the monitoring task
    client.loop.create_task(monitor_services())

# --- Run the Bot ---
if __name__ == "__main__":
    log_info("Starting Discord bot...")
    client.run(DISCORD_BOT_TOKEN)